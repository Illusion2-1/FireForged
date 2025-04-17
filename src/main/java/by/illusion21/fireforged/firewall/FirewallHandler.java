package by.illusion21.fireforged.firewall;

import by.illusion21.fireforged.Fireforged;
import by.illusion21.fireforged.config.entity.Action;
import by.illusion21.fireforged.firewall.utils.FirewallUtils;
import by.illusion21.fireforged.firewall.utils.RuleManager;
import by.illusion21.fireforged.proxyprotocol.ProxyParseResult;
import by.illusion21.fireforged.proxyprotocol.ProxyV2Parser;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil; // Important for releasing ByteBuf if consumed

import java.net.SocketAddress;
import java.net.UnknownHostException;

import by.illusion21.fireforged.config.FirewallConfig;
import org.slf4j.Logger;

public class FirewallHandler extends ChannelInboundHandlerAdapter {

    // State machine for parsing
    private enum State {
        INITIAL,            // Waiting for initial data
        BUFFERING,          // Accumulating potential PROXY header data
        PROCESSING_COMPLETE // Header processed (or skipped), forwarding data now
    }

    private State currentState = State.INITIAL;
    private ByteBuf accumulator = null; // Buffer for fragmented PROXY header
    private final boolean proxyEnabled = FirewallConfig.isProxyProtocolEnabled.get();
    private final static Logger LOGGER = Fireforged.getLogger();
    private final static RuleManager RULE_MANAGER = Fireforged.getRuleManager();

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        // Allocate the accumulator buffer immediately if proxy is enabled
        if (proxyEnabled) {
            // Size estimation: V2 header + reasonable max address info length
            accumulator = ctx.alloc().buffer(ProxyV2Parser.V2_MAX_HEADER_SIZE);
            currentState = State.BUFFERING;
        } else {
            // If proxy is disabled, potentially make the decision in channelActive
            currentState = State.INITIAL; // Or directly to PROCESSING_COMPLETE if check passes there
        }
        super.handlerAdded(ctx);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws UnknownHostException {
        SocketAddress initialRemoteAddress = ctx.channel().remoteAddress();
        LOGGER.debug("FirewallHandler active for initial address: {}", initialRemoteAddress);

        // If PROXY protocol is DISABLED, perform check on the direct address (127.0.0.1)
        // This might be useful to allowlist the frpc instance itself.
        if (!proxyEnabled) {
            // Handler removed, processing passed on
            Action action = RULE_MANAGER.getActionForIp(initialRemoteAddress);
            if (action != Action.ACCEPT) {
                LOGGER.info("Firewall: Denied connection from non-proxied source {}", initialRemoteAddress);
                FirewallUtils.closeConnection(ctx, action);
            } else {
                LOGGER.debug("Firewall: Allowed non-proxied source {}. Proceeding.", initialRemoteAddress);
                // Allowed, mark as complete and remove handler
                currentState = State.PROCESSING_COMPLETE;
                ctx.pipeline().remove(this);
                // Pass the active event down
                ctx.fireChannelActive();
            }
            return; // Stop processing, handler will be removed on channel close
        }

        // If proxy IS enabled, we wait for channelRead to get the header.
        // Just pass the active event down.
        ctx.fireChannelActive();
    }


    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws UnknownHostException {
        // If already processed, just forward the data
        if (currentState == State.PROCESSING_COMPLETE) {
            ctx.fireChannelRead(msg);
            return;
        }

        // only expect ByteBuf at this stage
        if (!(msg instanceof ByteBuf incoming)) {
            LOGGER.warn("FirewallHandler received unexpected message type: {}", msg.getClass().getName());
            ctx.fireChannelRead(msg); // Forward it anyway? Or close?
            return;
        }

        // If proxy is disabled, this handler should have been removed in channelActive.
        // If we reach here, something is wrong, but let's be safe.
        if (!proxyEnabled) {
            LOGGER.warn("FirewallHandler still active but proxy is disabled?");
            currentState = State.PROCESSING_COMPLETE;
            ctx.pipeline().remove(this);
            ctx.fireChannelRead(msg); // Forward the current message
            return;
        }

        // --- PROXY Protocol Handling ---
        if (currentState == State.BUFFERING) {
            // Append incoming data to our accumulator
            if (accumulator == null) { // Should have been created in handlerAdded
                LOGGER.error("FirewallHandler accumulator is null when buffering!");
                FirewallUtils.closeConnection(ctx);
                ReferenceCountUtil.release(msg);
                return;
            }
            accumulator.writeBytes(incoming);
            ReferenceCountUtil.release(msg); // Release the incoming buffer, data is now in accumulator

            // Try to parse the accumulated data
            ProxyParseResult result = ProxyV2Parser.parse(accumulator);

            switch (result.getStatus()) {
                case INCOMPLETE:
                    // Not enough data yet, keep buffering. Do nothing else.
                    LOGGER.trace("Firewall: PROXY header incomplete, waiting for more data from {}", ctx.channel().remoteAddress());
                    // Check if accumulator is getting excessively large (potential DoS)
                    if (accumulator.readableBytes() > ProxyV2Parser.V2_MAX_HEADER_SIZE * 2) { // Safety limit
                        LOGGER.warn("Firewall: PROXY accumulator exceeds safety limit for {}. Closing.", ctx.channel().remoteAddress());
                        FirewallUtils.closeConnection(ctx);
                        // accumulator released in handlerRemoved
                    }
                    break; // Wait for the next channelRead

                case SUCCESS:
                    LOGGER.info("Firewall: Parsed PROXY header for {}. Real IP: \033[1;32m{}\033[0m", ctx.channel().remoteAddress(), result.getRealAddress());

                    // Perform firewall check using the REAL source address
                    Action action = RULE_MANAGER.getActionForIp(result.getRealAddress());
                    if (action != Action.ACCEPT) {
                        LOGGER.info("Firewall: Denied connection from real IP {} (proxied via {})", result.getRealAddress(), ctx.channel().remoteAddress());
                        FirewallUtils.closeConnection(ctx, action);
                        // accumulator released in handlerRemoved
                        return;
                    }

                    // Allowed! Store the real IP
                    ctx.channel().attr(FirewallUtils.REAL_IP_KEY).set(result.getRealAddress());

                    // --- CRITICAL: Forward remaining data ---
                    // The accumulator now contains any payload data *after* the consumed header.
                    ByteBuf remainingPayload = Unpooled.EMPTY_BUFFER;
                    if (accumulator.isReadable()) {
                        // Retain the remaining payload to pass downstream
                        remainingPayload = accumulator.retainedSlice(); // Use retainedSlice to avoid copying if possible
                    }

                    // Mark processing as complete *before* removing handler
                    currentState = State.PROCESSING_COMPLETE;
                    // Remove this handler from the pipeline
                    ctx.pipeline().remove(this);
                    LOGGER.debug("Firewall: PROXY check passed. Handler removed for {}", result.getRealAddress());


                    // If there was payload data after the header, fire channelRead with it
                    if (remainingPayload.isReadable()) {
                        LOGGER.trace("Firewall: Forwarding {} bytes of payload after PROXY header.", remainingPayload.readableBytes());
                        ctx.fireChannelRead(remainingPayload);
                    } else {
                        // Release the empty buffer if we created one or the slice if it was empty
                        ReferenceCountUtil.release(remainingPayload);
                    }
                    // Original accumulator will be released in handlerRemoved

                    break; // Done with this read

                case NOT_PROXY: // Data received, but wasn't a valid PROXY header start
                case INVALID:   // Header started but was malformed
                    String logReason = result.getStatus() == ProxyParseResult.Status.INVALID ? "Invalid" : "No";
                    LOGGER.warn("Firewall: {} PROXY header found, but proxy is required for {}. Closing.", logReason, ctx.channel().remoteAddress());
                    FirewallUtils.closeConnection(ctx);
                    // accumulator released in handlerRemoved
                    break; // Done with this read
            }
        }
        // If currentState is still INITIAL or BUFFERING after processing, we wait for more data.
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        // Ensure the accumulator buffer is released when the handler is removed
        if (accumulator != null) {
            if (accumulator.refCnt() > 0) {
                ReferenceCountUtil.release(accumulator);
            }
            accumulator = null;
        }
        LOGGER.trace("FirewallHandler removed, accumulator released.");
        super.handlerRemoved(ctx);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        LOGGER.error("Exception in FirewallHandler for {}", ctx.channel().remoteAddress(), cause);
        FirewallUtils.closeConnection(ctx);
        // accumulator will be released in handlerRemoved when channel closes
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        // Ensure accumulator cleanup if channel closes unexpectedly
        if (accumulator != null) {
            if (accumulator.refCnt() > 0) {
                ReferenceCountUtil.release(accumulator);
            }
            accumulator = null;
        }
        super.channelInactive(ctx);
    }
}