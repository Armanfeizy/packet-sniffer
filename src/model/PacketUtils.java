package model;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TransportPacket;

@SuppressWarnings("unused")
public final class PacketUtils {
    public static String getIpByHex(String hex) {
        var ipLong = Long.parseLong(hex, 16);
        return String.format("%d.%d.%d.%d", ipLong >> 24,
                ipLong >> 16 & 0x00000000000000FF,
                ipLong >> 8 & 0x00000000000000FF,
                ipLong & 0x00000000000000FF);
    }

    public static boolean[] flagsOfIPv4(Packet p) {
        var res = new boolean[] {false, false, false};
        try {
            var ipv4 = p.get(IpV4Packet.class);
            res[0] = ipv4.getHeader().getReservedFlag();
            res[0] = ipv4.get(IpV4Packet.class).getHeader().getDontFragmentFlag();
            res[0] = ipv4.get(IpV4Packet.class).getHeader().getMoreFragmentFlag();
        } catch (Exception e) {
            return res;
        }
        return res;
    }

    public static String protocol(Packet p) {
        try {
            return p.get(IpV4Packet.class).getHeader().getProtocol().name();
        } catch (Exception e) {
            return "Unknown";
        }
    }

    public static int protocolNumber(Packet p) {
        try {
            return p.get(IpV4Packet.class).getHeader().getProtocol().value();
        } catch (Exception e) {
            return -1;
        }
    }

    public static String srcMacAddress(Packet p) {
        try {
            return p.get(EthernetPacket.class).getHeader().getSrcAddr().toString();
        } catch (Exception e) {
            return "null";
        }
    }

    public static String dstMacAddress(Packet p) {
        try {
            return p.get(EthernetPacket.class).getHeader().getDstAddr().toString();
        } catch (Exception e) {
            return "null";
        }
    }

    public static String id(Packet p) {
        try {
            return Integer.toString(p.get(IpV4Packet.class).getHeader().getIdentificationAsInt());
        } catch (Exception e) {
            return "null";
        }
    }

    public static String srcAddress(Packet p) {
        try {
            return p.get(IpV4Packet.class).getHeader().getSrcAddr().toString();
        } catch (Exception e) {
            return "null";
        }
    }

    public static String dstAddress(Packet p) {
        try {
            return p.get(IpV4Packet.class).getHeader().getDstAddr().toString();
        } catch (Exception e) {
            return "null";
        }
    }

    public static String ttl(Packet p) {
        try {
            return Integer.toString(p.get(IpV4Packet.class).getHeader().getTtlAsInt());
        } catch (Exception e) {
            return "null";
        }
    }

    public static int srcPort(Packet p) {
        try {
            return p.get(TransportPacket.class).getHeader().getSrcPort().valueAsInt();
        } catch (Exception e) {
            return -1;
        }
    }

    public static int dstPort(Packet p) {
        try {
            return p.get(TransportPacket.class).getHeader().getDstPort().valueAsInt();
        } catch (Exception e) {
            return -1;
        }
    }

    public static int ipVersion(byte[] header) {
        return getIntOfByteArray(header, 0, 3);
    }

    public static int ipHeaderLen(byte[] header) {
        return getIntOfByteArray(header, 4, 7);
    }

    public static int ipTypeOfService(byte[] header) {
        return getIntOfByteArray(header, 8, 15);
    }

    public static int ipIdOfPacket(byte[] header) {
        return getIntOfByteArray(header, 32, 47);
    }

    public static int ipFlags(byte[] header) {
        return getIntOfByteArray(header, 48, 50);
    }

    public static int ipFragmentOffset(byte[] header) {
        return getIntOfByteArray(header, 51, 63);
    }

    public static int ipTTL(byte[] header) {
        return getIntOfByteArray(header, 64, 71);
    }

    public static int ipProtocol(byte[] header) {
        return getIntOfByteArray(header, 72, 79);
    }

    public static int ipHeaderChecksum(byte[] header) {
        return getIntOfByteArray(header, 80, 85);
    }

    public static int ipSourceIpAddress(byte[] header) {
        return getIntOfByteArray(header, 86, 117);
    }

    public static int ipDestinationIpAddress(byte[] header) {
        return getIntOfByteArray(header, 118, 149);
    }

    public static int getIntOfByteArray(byte[] bytes, int startInclusive, int endInclusive) {
        int res = 0;
        for (int i = startInclusive; i <= endInclusive; i++)
            res |= (bytes[i] & 0xFF) << (24 - 8 * i);
        return res;
    }
}
