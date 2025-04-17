package by.illusion21.fireforged.proxyprotocol;

import by.illusion21.fireforged.Fireforged;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;

@SuppressWarnings("ReassignedVariable")
public class ProxyV2Parser {
    private static final Logger logger = Fireforged.getLogger();
    // HAProxy v2 constants
    private static final byte[] V2_SIGNATURE = {
            (byte) 0x0D, (byte) 0x0A, (byte) 0x0D, (byte) 0x0A, (byte) 0x00,
            (byte) 0x0D, (byte) 0x0A, (byte) 0x51, (byte) 0x55, (byte) 0x49,
            (byte) 0x54, (byte) 0x0A
    };
    private static final int V2_SIGNATURE_LENGTH = V2_SIGNATURE.length; // 12
    private static final int V2_HEADER_MIN_SIZE = 16; // Signature + version/cmd + family/proto + length
    public static final int V2_MAX_HEADER_SIZE = 216 + V2_HEADER_MIN_SIZE; // Max addr info len = 216

    // Version 2, PROXY command
    private static final byte AF_INET = 0x10;
    private static final byte AF_INET6 = 0x20;
    private static final byte AF_UNSPEC = 0x00; // LOCAL command often uses UNSPEC
    private static final byte PROTO_TCP = 0x01;
    private static final byte PROTO_UNSPEC = 0x00;

    /**
     * Attempts to parse a HAProxy v2 header from the buffer.
     * IMPORTANT: This method advances the readerIndex of the buffer ONLY if a
     * complete and valid header is found and consumed.
     *
     * @param buffer The buffer containing potential header data.
     * @return A ProxyParseResult indicating success, failure, or incomplete data.
     */
    public static ProxyParseResult parse(ByteBuf buffer) {
        int initialReaderIndex = buffer.readerIndex();

        // 1. Check minimum length for signature + basic fields
        if (buffer.readableBytes() < V2_HEADER_MIN_SIZE) {
            return ProxyParseResult.incomplete();
        }

        // 2. Check signature
        for (int i = 0; i < V2_SIGNATURE_LENGTH; i++) {
            if (buffer.getByte(initialReaderIndex + i) != V2_SIGNATURE[i]) {
                // Doesn't match the required signature
                return ProxyParseResult.notProxy();
            }
        }

        // 3. Check Version and Command byte
        byte versionAndCommand = buffer.getByte(initialReaderIndex + V2_SIGNATURE_LENGTH);
        if ((versionAndCommand & 0xF0) != 0x20) { // Check version bits (must be 2)
            return ProxyParseResult.invalid("Invalid PROXY v2 version");
        }
        if ((versionAndCommand & 0x0F) != 0x01) { // Check command bits (must be 0x01 for PROXY)
            // Could be 0x00 for LOCAL command, handle if needed, otherwise treat as invalid/not proxy
            return ProxyParseResult.notProxy("Not PROXY command"); // Or invalid
        }

        // 4. Read Address Family and Protocol
        byte familyAndProto = buffer.getByte(initialReaderIndex + V2_SIGNATURE_LENGTH + 1);
        byte family = (byte) (familyAndProto & 0xF0);
        byte proto = (byte) (familyAndProto & 0x0F); // We expect TCP (0x01)

        // We primarily care about TCP for Minecraft
        if (proto != PROTO_TCP && proto != PROTO_UNSPEC) {
            return ProxyParseResult.invalid("Unsupported PROXY protocol (expected TCP)");
        }

        // 5. Read Address Info Length
        int addressInfoLength = buffer.getUnsignedShort(initialReaderIndex + V2_SIGNATURE_LENGTH + 2);

        // 6. Check if we have enough data for the full header including address info
        int totalHeaderSize = V2_HEADER_MIN_SIZE + addressInfoLength;
        if (buffer.readableBytes() < totalHeaderSize) {
            return ProxyParseResult.incomplete();
        }

        // --- We have the full header data ---

        // 7. Parse Address Info based on family
        SocketAddress sourceAddress;
        SocketAddress destAddress = null; // might not need destination
        int addressInfoOffset = initialReaderIndex + V2_HEADER_MIN_SIZE;

        try {
            switch (family) {
                case AF_INET: // IPv4
                    // Expected structure: src_addr (4), dst_addr (4), src_port (2), dst_port (2) = 12 bytes
                    if (addressInfoLength < 12) return ProxyParseResult.invalid("INET address info too short");
                    byte[] srcIp4 = new byte[4];
                    byte[] dstIp4 = new byte[4];
                    buffer.getBytes(addressInfoOffset, srcIp4);
                    buffer.getBytes(addressInfoOffset + 4, dstIp4);
                    int srcPort4 = buffer.getUnsignedShort(addressInfoOffset + 8);
                    int dstPort4 = buffer.getUnsignedShort(addressInfoOffset + 10);
                    sourceAddress = new InetSocketAddress(InetAddress.getByAddress(srcIp4), srcPort4);
                    destAddress = new InetSocketAddress(InetAddress.getByAddress(dstIp4), dstPort4);
                    break;

                case AF_INET6: // IPv6, unlikely from frpc
                    // Expected structure: src_addr (16), dst_addr (16), src_port (2), dst_port (2) = 36 bytes
                    if (addressInfoLength < 36) return ProxyParseResult.invalid("INET6 address info too short");
                    byte[] srcIp6 = new byte[16];
                    byte[] dstIp6 = new byte[16];
                    buffer.getBytes(addressInfoOffset, srcIp6);
                    buffer.getBytes(addressInfoOffset + 16, dstIp6);
                    int srcPort6 = buffer.getUnsignedShort(addressInfoOffset + 32);
                    int dstPort6 = buffer.getUnsignedShort(addressInfoOffset + 34);
                    sourceAddress = new InetSocketAddress(InetAddress.getByAddress(srcIp6), srcPort6);
                    destAddress = new InetSocketAddress(InetAddress.getByAddress(dstIp6), dstPort6);
                    break;

                case AF_UNSPEC: // Usually for LOCAL command, no address info expected? Or Unix socket path?
                    // For PROXY command with UNSPEC, behavior might vary. Assume no useful IP.
                    // If frpc sends this, will need to know what data follows.
                    // Treat as invalid or (handle specifically if frpc uses it meaningfully - no waaaaaaaay) .
                    logger.error("\033[1;31mPROXY header has UNSPEC family.\033[0m");
                    return ProxyParseResult.invalid("UNSPEC address family not handled");

                default:
                    return ProxyParseResult.invalid("Unknown address family");
            }
        } catch (UnknownHostException e) {
            return ProxyParseResult.invalid("Failed to resolve IP address from PROXY header");
        } catch (Exception e) {
            logger.error("\033[1;31mError parsing PROXY address details\033[0m", e);
            return ProxyParseResult.invalid("Exception during address parsing");
        }

        // If we got here, parsing was successful!
        // CRITICAL: Advance the reader index past the consumed header
        buffer.readerIndex(initialReaderIndex + totalHeaderSize);

        // Return success with the crucial source address
        return ProxyParseResult.success(sourceAddress);
    }
}