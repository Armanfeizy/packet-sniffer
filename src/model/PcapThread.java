package model;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.Arrays;

public class PcapThread implements Runnable {
    private Thread pcapThread;
    private boolean isCapturing;
    private PcapHandle handle;
    private final ArrayList<PacketListener> packetListeners;
    private String networkInterfaceName;
    private String filter;

    public PcapThread(PacketListener... packetListeners) {
        isCapturing = false;
        this.packetListeners = new ArrayList<>(packetListeners.length);
        this.packetListeners.addAll(Arrays.asList(packetListeners));
        networkInterfaceName = "\\Device\\NPF_{A71F6B3E-EA76-48CD-8312-B35114874984}";
        filter = "";
    }

    public synchronized void start(String networkInterfaceName, String filter) {
        if (isCapturing)
            return;

        this.networkInterfaceName = networkInterfaceName;
        this.filter = filter;

        PcapHandle.Builder phb =
                new PcapHandle.Builder(networkInterfaceName)
                        .snaplen(65535)
                        .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                        .timeoutMillis(10)
                        .bufferSize(1024 * 1024);

        handle = null;
        try {
            handle = phb.build();
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
        }

        isCapturing = true;
        DataSet.isCapturing = true;
        pcapThread = new Thread(this);
        pcapThread.start();
    }

    public synchronized void start() {
        start(networkInterfaceName, filter);
    }

    public synchronized void stop() {
        if (!isCapturing)
            return;
        isCapturing = false;
        DataSet.isCapturing = false;
        try {
            pcapThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            handle = null;
        }
    }

    public synchronized void addPacketListener(PacketListener... packetListeners) {
        this.packetListeners.addAll(Arrays.asList(packetListeners));
    }

    public String getFilter() {
        return filter;
    }

    public void asyncSetOfNIFAndFilter(String networkInterfaceName, String filter) {
        this.filter = filter;
        this.networkInterfaceName = networkInterfaceName;
    }

    @Override
    public void run() {
        while (isCapturing) {
            Packet packet;
            try {
                packet = handle.getNextPacket();
            } catch (NotOpenException e) {
                e.printStackTrace();
                isCapturing = false;
                DataSet.isCapturing = false;
                break;
            }
            if (packet != null)
                packetListeners.forEach(e -> e.gotPacket(packet));
        }
        handle.close();
    }

    public static PcapThread buildAndRun(String networkInterfaceName, String filter, PacketListener packetListener) {
        var pt = new PcapThread(packetListener);
        pt.start(networkInterfaceName, filter);
        return pt;
    }
}
