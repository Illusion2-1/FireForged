package by.illusion21.fireforged.proxyprotocol;

import java.net.SocketAddress;
import javax.annotation.Nullable;

public class ProxyParseResult {

    public enum Status {
        SUCCESS,      // Header parsed successfully
        INCOMPLETE,   // Need more data
        NOT_PROXY,    // Data doesn't start with PROXY signature/command
        INVALID       // Header started but is malformed
    }

    private final Status status;
    @Nullable private final SocketAddress realAddress; // Only valid if status is SUCCESS
    @Nullable private final String errorReason;      // Optional reason for INVALID

    // Private constructors, use static factory methods
    private ProxyParseResult(Status status, @Nullable SocketAddress realAddress, @Nullable String errorReason) {
        this.status = status;
        this.realAddress = realAddress;
        this.errorReason = errorReason;
    }

    public static ProxyParseResult success(SocketAddress realAddress) {
        return new ProxyParseResult(Status.SUCCESS, realAddress, null);
    }

    public static ProxyParseResult incomplete() {
        return new ProxyParseResult(Status.INCOMPLETE, null, null);
    }

    public static ProxyParseResult notProxy() {
        return new ProxyParseResult(Status.NOT_PROXY, null, null);
    }

    public static ProxyParseResult notProxy(String reason) {
        return new ProxyParseResult(Status.NOT_PROXY, null, reason);
    }

    public static ProxyParseResult invalid(String reason) {
        return new ProxyParseResult(Status.INVALID, null, reason);
    }

    public Status getStatus() {
        return status;
    }

    @Nullable
    public SocketAddress getRealAddress() {
        // Consider adding check: if (status != Status.SUCCESS) throw new IllegalStateException();
        return realAddress;
    }

    @Nullable
    public String getErrorReason() {
        return errorReason;
    }
}