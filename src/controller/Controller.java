package controller;

import model.PcapThread;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.namednumber.EtherType;
import utils.managers.TTManager;
import view.WindowFrame;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.Arrays;

import static model.DataSet.*;
import static model.PacketUtils.*;

public class Controller {
    public static final WindowFrame window;
    public static final PcapThread pcapThread;

    /*
                "No.", "ID", "Length", "Source IP", "Destination IP",
                "Protocol", "Data As String", "Source MAC Address", "Destination MAC Address", "TTL", "srcPort", "dstPort"
    */

    static {
        window = new WindowFrame();
        pcapThread = new PcapThread(
                p -> {
                    Object[] row = new Object[12];
                    row[0] = ++totalCount;
                    row[1] = id(p);
                    row[2] = p.length();
                    row[3] = srcAddress(p);
                    row[4] = dstAddress(p);
                    row[5] = protocol(p);
                    row[6] = new String(Arrays.copyOfRange(p.getRawData(), p.getHeader().length(), 32));
                    row[7] = srcMacAddress(p);
                    row[8] = dstMacAddress(p);
                    row[9] = ttl(p);
                    row[10] = srcPort(p);
                    row[11] = dstPort(p);
                    switch (protocolNumber(p)) {
                        case 1 -> {
                            icmpCount++;
                            tlpStatPieDS.setValue(protocol(p), icmpCount);
                        }
                        case 2 -> {
                            igmpCount++;
                            tlpStatPieDS.setValue(protocol(p), igmpCount);
                        }
                        case 6 -> {
                            tcpCount++;
                            tlpStatPieDS.setValue(protocol(p), tcpCount);
                        }
                        case 17 -> {
                            udpCount++;
                            tlpStatPieDS.setValue(protocol(p), udpCount);
                        }
                        case 47 -> {
                            greCount++;
                            tlpStatPieDS.setValue(protocol(p), greCount);
                        }
                        default -> {
                            if (p.contains(IpV6Packet.class) || p.contains(ArpPacket.class))
                                return;
                            tlpOtherCount++;
                            tlpStatPieDS.setValue("Others", tlpOtherCount);
                        }
                    }
                    if (p.contains(ArpPacket.class))
                        arpCount++;
                    totalSize += p.length();
                    if (maxSize < p.length())
                        maxSize = p.length();
                    if (minSize > p.length() && p.length() != 0)
                        minSize = p.length();

                    var srcD = ipPcapCount.getOrDefault(srcAddress(p), new int[] {0, 0, 0, 0});
                    var dstD = ipPcapCount.getOrDefault(dstAddress(p), new int[] {0, 0, 0, 0});
                    ipPcapCount.put(srcAddress(p), new int[] {srcD[0]+1, srcD[1], srcD[2]+p.length(), srcD[3]});
                    ipPcapCount.put(dstAddress(p), new int[] {dstD[0], dstD[1]+1, dstD[2], dstD[3]+p.length()});

                    boolean notFind = true;
                    for (var port : new int[] {dstPort(p), srcPort(p)})
                        if (notFind)
                            switch (port) {
                                case 80, 443, 593 -> {
                                    httpCount++;
                                    alpStatPieDS.setValue("HTTP", httpCount);
                                    notFind = false;
                                }
                                case 20, 21, 989, 990 -> {
                                    ftpCount++;
                                    alpStatPieDS.setValue("FTP", ftpCount);
                                    notFind = false;
                                }
                                case 53, 135, 853 -> {
                                    dnsCount++;
                                    alpStatPieDS.setValue("DNS", dnsCount);
                                    notFind = false;
                                }
                                case 25, 465, 587, 3535, 10024, 10025 -> {
                                    smtpCount++;
                                    alpStatPieDS.setValue("SMTP", smtpCount);
                                    notFind = false;
                                }
                                case 110, 995 -> {
                                    pop3Count++;
                                    alpStatPieDS.setValue("POP3", pop3Count);
                                    notFind = false;
                                }
                                case 23, 107, 992 -> {
                                    telnetCount++;
                                    alpStatPieDS.setValue("Telnet", telnetCount);
                                    notFind = false;
                                }
                                case 69 -> {
                                    tftpCount++;
                                    alpStatPieDS.setValue("TFTP", tftpCount);
                                    notFind = false;
                                }
                            }
                    if (notFind) {
                        alpOtherCount++;
                        alpStatPieDS.setValue("Others", alpOtherCount);
                    }
                    packetsInfo.add(p.toString());

                    if (p.get(EthernetPacket.class).getHeader().getType().equals(EtherType.IPV4)) {
                        var ff=  flagsOfIPv4(p);
                        flagsDS.setValue(flagsDS.getValue(0, 0).intValue() + (ff[0] ? 1 : 0), "F", "Reserved");
                        flagsDS.setValue(flagsDS.getValue(0, 1).intValue() + (!ff[0] ? 1 : 0), "F", "Don't Reserved");
                        flagsDS.setValue(flagsDS.getValue(0, 2).intValue() + (!ff[1] ? 1 : 0), "F", "Fragmented");
                        flagsDS.setValue(flagsDS.getValue(0, 3).intValue() + (ff[1] ? 1 : 0), "F", "Don't Fragmented");
                        flagsDS.setValue(flagsDS.getValue(0, 4).intValue() + (ff[2] ? 1 : 0), "F", "More Fragment");
                        flagsDS.setValue(flagsDS.getValue(0, 5).intValue() + (!ff[2] ? 1 : 0), "F", "No More Fragment");
                    }

                    window.getStatisticLabel().setText(
                            "Arrived: " + totalCount + " packets, totalSize: " + totalSize + " bytes, maxSize: " + maxSize +
                                    " bytes, minSize: " + minSize + " bytes, avgSize: " + (totalSize / Math.max(totalCount, 0)) + " bytes.");
                    window.insertPacket(row);
                    if ((int) TTManager.secondsAfterStart() % 3 != 0 || !isCapturing)
                        return;
                    try {
                        var model = (DefaultTableModel) ((JTable) ((JViewport) ((JScrollPane)
                                window.getTabbedPane().getComponentAt(3)).getComponent(0)).getComponent(0)).getModel();
                        model.setRowCount(0);
                        int counter = 0;
                        for (var kv : ipPcapCount.entrySet())
                            try {
                                model.addRow(new Object[] {++counter, kv.getKey().substring(1), kv.getValue()[0], kv.getValue()[1], kv.getValue()[2], kv.getValue()[3]});
                            } catch (Exception e) {
                                break;
                            }
                    } catch (Exception ignore) {}
                }
        );
    }


    /*
    *
    *
[Ethernet Header (14 bytes)]
  Destination address: f8:1a:67:65:f3:98
  Source address: f0:03:8c:ac:41:dd
  Type: 0x0800 (IPv4)
[IPv4 Header (20 bytes)]
  Version: 4 (IPv4)
  IHL: 5 (20 [bytes])
  TOS: [precedence: 0 (Routine)] [tos: 0 (Default)] [mbz: 0]
  Total length: 40 [bytes]
  Identification: 54531
  Flags: (Reserved, Don't Fragment, More Fragment) = (false, true, false)
  Fragment offset: 0 (0 [bytes])
  TTL: 64
  Protocol: 6 (TCP)
  Header checksum: 0x93ad
  Source address: /192.168.1.103
  Destination address: /8.8.8.8
[TCP Header (20 bytes)]
  Source port: 63023 (unknown)
  Destination port: 443 (HTTPS)
  Sequence Number: 4285104986
  Acknowledgment Number: 1274651190
  Data Offset: 5 (20 [bytes])
  Reserved: 0
  URG: false
  ACK: true
  PSH: false
  RST: false
  SYN: false
  FIN: false
  Window: 514
  Checksum: 0x72d4
  Urgent Pointer: 0

    * */

    private Controller() {
    }
}
