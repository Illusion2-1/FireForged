package by.illusion21.fireforged.proxyprotocol;


import by.illusion21.fireforged.proxyprotocol.utils.ProxyParseResult;
import by.illusion21.fireforged.proxyprotocol.utils.ProxyV2Parser;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;

import java.net.SocketAddress;
import java.util.Objects;

/// Handles the logic for parsing the HAProxy PROXY protocol header (v2).
/// This class is Minecraft-independent and manages the state for a single connection's
/// proxy header parsing attempt.
/// NOTE: This class is stateful and designed for single use per connection attempt.
public class ProxyProtocolProcessor {

    public static class ProcessingResult {
        public enum Status {
            SUCCESS,
            FAILURE,
            INCOMPLETE
        }

        private final Status status;
        private final SocketAddress realAddress;
        private final ByteBuf remainingData;
        private final String failureReason;

        private ProcessingResult(Status status, SocketAddress realAddress, ByteBuf remainingData, String failureReason) {
            this.status = status;
            this.realAddress = realAddress;
            this.remainingData = remainingData;
            this.failureReason = failureReason;
        }

        public static ProcessingResult success(SocketAddress realAddress, ByteBuf remainingData) {
            return new ProcessingResult(Status.SUCCESS, Objects.requireNonNull(realAddress), remainingData, null);
        }

        public static ProcessingResult failure(String reason) {
            return new ProcessingResult(Status.FAILURE, null, null, reason);
        }

        public static ProcessingResult incomplete() {
            return new ProcessingResult(Status.INCOMPLETE, null, null, null);
        }

        public Status getStatus() {
            return status;
        }

        public SocketAddress getRealAddress() {
            return realAddress;
        }

        public ByteBuf getRemainingData() {
            return remainingData;
        }

        public String getFailureReason() {
            return failureReason;
        }
    }

    private final Logger logger;
    private final SocketAddress originalRemoteAddress; // For logging context
    private ByteBuf accumulator;
    private boolean processingComplete = false;

    public ProxyProtocolProcessor(Logger logger, SocketAddress originalRemoteAddress) {
        this.logger = Objects.requireNonNull(logger, "Logger cannot be null");
        this.originalRemoteAddress = Objects.requireNonNull(originalRemoteAddress, "Original remote address cannot be null");
        logger.trace("ProxyProtocolProcessor created for {}", originalRemoteAddress);
    }

    /**
     * Processes incoming data, attempting to parse the PROXY protocol header.
     *
     * @param allocator The ByteBufAllocator to create the initial buffer if needed.
     * @param data      The incoming data buffer. The caller *must release* this buffer
     *                  after calling this method, unless it's incorporated into the
     *                  ProcessingResult's remainingData.
     * @return A ProcessingResult indicating the outcome.
     */
    public ProcessingResult processData(ByteBufAllocator allocator, ByteBuf data) {
        if (processingComplete) {
            logger.warn("processData called after processing was already complete for {}", originalRemoteAddress);
            return ProcessingResult.failure("Processing already complete");
        }

        if (accumulator == null) {
            accumulator = allocator.buffer(ProxyV2Parser.V2_MAX_HEADER_SIZE);
            logger.trace("Allocated accumulator buffer for {}", originalRemoteAddress);
        }

        try {
            accumulator.writeBytes(data);
        } catch (IndexOutOfBoundsException e) {
            logger.warn("PROXY header buffer write failed (likely exceeded max size {}) from {}. Closing connection.",
                    ProxyV2Parser.V2_MAX_HEADER_SIZE, originalRemoteAddress);
            processingComplete = true;
            return ProcessingResult.failure("Header buffer write failed");
        }

        ProxyParseResult parseResult = ProxyV2Parser.parse(accumulator);

        switch (parseResult.getStatus()) {
            case SUCCESS:
                processingComplete = true;
                SocketAddress realAddress = parseResult.getRealAddress();
                if (realAddress == null) {
                    logger.error("PROXY header parsed successfully but real address is null from {}.", originalRemoteAddress);
                    return ProcessingResult.failure("Parsed successfully but address is null");
                }

                ByteBuf remainingData = null;
                if (accumulator.isReadable()) {
                    remainingData = accumulator.readRetainedSlice(accumulator.readableBytes());
                    logger.trace("Passing {} bytes of remaining data after PROXY header for {}.", remainingData.readableBytes(), originalRemoteAddress);
                } else {
                    logger.trace("No remaining data after PROXY header for {}.", originalRemoteAddress);
                }
                return ProcessingResult.success(realAddress, remainingData);

            case INCOMPLETE:
                if (accumulator.readableBytes() > ProxyV2Parser.V2_MAX_HEADER_SIZE) {
                    logger.warn("PROXY header buffer exceeded max size ({}) from {}. Closing connection.",
                            ProxyV2Parser.V2_MAX_HEADER_SIZE, originalRemoteAddress);
                    processingComplete = true;
                    return ProcessingResult.failure("Header too large");
                }
                logger.trace("PROXY header incomplete for {}, waiting for more data ({} bytes received).", originalRemoteAddress, accumulator.readableBytes());
                return ProcessingResult.incomplete();

            default: // INVALID or NOT_PROXY
                logger.warn("Invalid or non-PROXY protocol header detected from {}. Status: {}",
                        originalRemoteAddress, parseResult.getStatus());
                processingComplete = true;
                return ProcessingResult.failure("Invalid/Unsupported header (" + parseResult.getStatus() + ")");
        }
    }


    public void releaseResources() {
        if (accumulator != null) {
            ReferenceCountUtil.release(accumulator);
            accumulator = null;
            logger.trace("Released accumulator buffer for {}", originalRemoteAddress);
        }
        processingComplete = true; // Ensure no further processing attempts
    }

    public boolean isProcessingComplete() {
        return processingComplete;
    }
    
    
}