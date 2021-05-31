package model;

import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;

import java.util.ArrayList;
import java.util.HashMap;

public final class DataSet {
    public static int tcpCount = 0;
    public static int udpCount = 0;
    public static int httpCount = 0;
    public static int dnsCount = 0;
    public static int icmpCount = 0;
    public static int igmpCount = 0;
    public static int arpCount = 0;
    public static int greCount = 0;
    public static int smtpCount = 0;
    public static int pop3Count = 0;
    public static int telnetCount = 0;
    public static int tftpCount = 0;
    public static int totalSize = 0;
    public static int alpOtherCount = 0;
    public static int tlpOtherCount = 0;
    public static int minSize = Integer.MAX_VALUE;
    public static int maxSize = 0;
    public static int totalCount = 0;
    public static int ftpCount = 0;
    public static boolean isCapturing = false;
    public static String selectedNIF = "\\Device\\NPF_{A71F6B3E-EA76-48CD-8312-B35114874984}";
    public final static DefaultPieDataset tlpStatPieDS = new DefaultPieDataset();
    public final static DefaultPieDataset alpStatPieDS = new DefaultPieDataset();
    public final static DefaultCategoryDataset flagsDS = new DefaultCategoryDataset();
    public final static HashMap<String, int[]> ipPcapCount = new HashMap<>();
    public static final ArrayList<String> packetsInfo = new ArrayList<>();

    static {
        flagsDS.addValue(0, "F", "Reserved");
        flagsDS.addValue(0, "F", "Don't Reserved");
        flagsDS.addValue(0, "F", "Fragmented");
        flagsDS.addValue(0, "F", "Don't Fragmented");
        flagsDS.addValue(0, "F", "More Fragment");
        flagsDS.addValue(0, "F", "No More Fragment");
    }

    public synchronized static void resetAll() {
        tcpCount = 0;
        udpCount = 0;
        httpCount = 0;
        dnsCount = 0;
        icmpCount = 0;
        igmpCount = 0;
        arpCount = 0;
        greCount = 0;
        smtpCount = 0;
        pop3Count = 0;
        telnetCount = 0;
        tftpCount = 0;
        totalSize = 0;
        alpOtherCount = 0;
        tlpOtherCount = 0;
        minSize = Integer.MAX_VALUE;
        maxSize = 0;
        totalCount = 0;
        ftpCount = 0;
        flagsDS.clear();
        alpStatPieDS.clear();
        tlpStatPieDS.clear();
        ipPcapCount.clear();
        packetsInfo.clear();
        flagsDS.addValue(0, "", "Reserved");
        flagsDS.addValue(0, "", "Don't Reserved");
        flagsDS.addValue(0, "", "Fragmented");
        flagsDS.addValue(0, "", "Don't Fragmented");
        flagsDS.addValue(0, "", "More Fragment");
        flagsDS.addValue(0, "", "No More Fragment");
    }

    public static String getSummery() {
        return "Total Packet No.: " + totalCount + "\nTCP No.: " + tcpCount +
                "\nUDP No.: " + udpCount + "\nICMP No.: " + icmpCount +
                "\nIGMP No.: " + igmpCount + "\nARP No.: " + arpCount +
                "\nGRE No.: " + greCount + "\nFTP No.: " + ftpCount +
                "\nHTTP No.: " + httpCount + "\nTFTP No.: " + tftpCount +
                "\nMaxSize: " + maxSize + "\nMinSize: " + minSize +
                "\nAvgSize: " + (totalSize / totalCount) + "\nTotalReceivedSize: " + totalSize + "\n";
    }
}
