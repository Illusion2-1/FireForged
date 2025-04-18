package by.illusion21.fireforged.proxyprotocol;

// FIXME: Decoupling proxy parser into a dedicated pipeline handler had yielded more timing synchronization issues and mitigations that may affect performance thus have been taken, which, not best suits what i desired, introduced a more complex structure. I hope that it won't produce any strange exceptions, so that i don't have to make further mitigations. And hopefully it doesn't cause large impact to performance.

import by.illusion21.fireforged.Fireforged;
import by.illusion21.fireforged.config.FirewallConfig;
import by.illusion21.fireforged.event.RealIpResolvedEvent;
import by.illusion21.fireforged.proxyprotocol.utils.ProxyParseResult;
import by.illusion21.fireforged.proxyprotocol.utils.ProxyV2Parser;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;
import net.minecraftforge.common.MinecraftForge;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

/**
 * Handles the HAProxy PROXY protocol (v1 or v2) to determine the real client address.
 * If the PROXY protocol is enabled, this handler parses the header, stores the real
 * client address in a Channel Attribute (REAL_REMOTE_ADDRESS), and removes itself.
 * If the protocol is disabled, it stores the original remote address in the attribute
 * and removes itself immediately.
 * <p>
 * NOTE: This handler is stateful and therefore NOT @Sharable. A new instance must be
 * created for each channel pipeline.
 */
public class ProxyHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOGGER = Fireforged.getLogger();

    /**
     * AttributeKey to store the real remote address (either from PROXY protocol
     * or the original address if the protocol is disabled).
     * Downstream handlers should use getRealRemoteAddress(channel) to retrieve it.
     */
    public static final AttributeKey<SocketAddress> REAL_REMOTE_ADDRESS = AttributeKey.newInstance("realRemoteAddress");

    private ByteBuf accumulator;
    private boolean proxyHeaderParsed = false;


    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        if (!FirewallConfig.isProxyProtocolEnabled.get()) {
            SocketAddress originalAddress = ctx.channel().remoteAddress();
            ctx.channel().attr(REAL_REMOTE_ADDRESS).set(originalAddress);
            LOGGER.trace("Proxy protocol disabled. Using original address: {}", originalAddress);
            proxyHeaderParsed = true;
            ctx.pipeline().remove(this);
            return;
        }

        LOGGER.debug("Proxy protocol enabled for {}. Waiting for header.", ctx.channel().remoteAddress());
        accumulator = ctx.alloc().buffer(ProxyV2Parser.V2_MAX_HEADER_SIZE);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        // If parsing already completed (e.g., protocol disabled, or header parsed successfully/failed),
        // just forward the message. The handler should have been removed already, but this is a safeguard.
        if (proxyHeaderParsed) {
            ctx.fireChannelRead(msg);
            return;
        }

        // Should only happen if protocol is enabled
        if (accumulator == null) {
            // Should not happen if logic in handlerAdded is correct, but handle defensively
            LOGGER.error("Accumulator is null unexpectedly for channel {}", ctx.channel().id());
            ctx.fireChannelRead(msg);
            releaseAndRemove(ctx);
            return;
        }

        if (!(msg instanceof ByteBuf data)) {
            LOGGER.warn("Received non-ByteBuf message before PROXY header parsed from {}. Message type: {}",
                    ctx.channel().remoteAddress(), msg.getClass().getName());
            handleProxyHeaderInvalid(ctx, "Received non-ByteBuf before header");
            ReferenceCountUtil.release(msg);
            return;
        }

        try {
            accumulator.writeBytes(data);
            ProxyParseResult result = ProxyV2Parser.parse(accumulator);

            switch (result.getStatus()) {
                case INCOMPLETE:
                    if (accumulator.readableBytes() > ProxyV2Parser.V2_MAX_HEADER_SIZE) {
                        LOGGER.warn("PROXY header buffer exceeded max size ({}) from {}. Closing connection.",
                                ProxyV2Parser.V2_MAX_HEADER_SIZE, ctx.channel().remoteAddress());
                        handleProxyHeaderInvalid(ctx, "Header too large");
                    }
                    break;
                case SUCCESS:
                    handleProxyHeaderSuccess(ctx, result);
                    break;
                default: // INVALID or NOT_PROXY
                    LOGGER.warn("Invalid or non-PROXY protocol header detected from {}. Status: {}",
                            ctx.channel().remoteAddress(), result.getStatus());
                    handleProxyHeaderInvalid(ctx, "Invalid/Unsupported header");
                    break;
            }
        } finally {
            ReferenceCountUtil.release(data);
        }
    }

    /**
     * Cleans up resources (accumulator) and removes this handler from the pipeline.
     * Should be called once parsing is definitively finished (success, failure, or disabled).
     *
     * @param ctx ChannelHandlerContext
     */
    private void releaseAndRemove(ChannelHandlerContext ctx) {
        proxyHeaderParsed = true; // Mark parsing as completed
        if (accumulator != null) {
            ReferenceCountUtil.release(accumulator);
            accumulator = null;
        }
        if (ctx.pipeline().context(this) != null) {
            ctx.pipeline().remove(this);
            LOGGER.trace("ProxyHandler removed from pipeline for channel {}", ctx.channel().id());
        }
    }


    private void handleProxyHeaderSuccess(ChannelHandlerContext ctx, ProxyParseResult result) {
        SocketAddress realAddress = result.getRealAddress();
        if (realAddress == null) {
            // Parser should ideally not return SUCCESS with null address, but handle defensively
            LOGGER.error("PROXY header parsed successfully but real address is null from {}. Closing.", ctx.channel().remoteAddress());
            handleProxyHeaderInvalid(ctx, "Parsed successfully but address is null");
            return;
        }

        ctx.channel().attr(REAL_REMOTE_ADDRESS).set(realAddress);
        fireRealIpResolvedEvent(ctx, realAddress);
        LOGGER.info("PROXY protocol parsed successfully for {}. Real client: {}", ctx.channel().remoteAddress(), realAddress);

        if (accumulator.isReadable()) {
            ByteBuf remainingData = accumulator.readRetainedSlice(accumulator.readableBytes());
            LOGGER.trace("Forwarding {} bytes of remaining data after PROXY header.", remainingData.readableBytes());
            ctx.fireChannelRead(remainingData);
        } else {
            LOGGER.trace("No remaining data after PROXY header.");
        }

        releaseAndRemove(ctx);
    }

    private void handleProxyHeaderInvalid(ChannelHandlerContext ctx, String reason) {
        LOGGER.warn("Invalid PROXY header processing from {}: {}. Closing connection.", ctx.channel().remoteAddress(), reason);

        ctx.close();
        releaseAndRemove(ctx);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        if (accumulator != null) {
            LOGGER.trace("Releasing accumulator in handlerRemoved for channel {}", ctx.channel().id());
            ReferenceCountUtil.release(accumulator);
            accumulator = null;
        }
        LOGGER.trace("ProxyHandler fully removed callback for channel {}", ctx.channel().id());
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        LOGGER.error("Exception in ProxyHandler for channel {}: {}", ctx.channel().id(), cause.getMessage(), cause);
        ctx.close();
        releaseAndRemove(ctx);
    }

    /**
     * Retrieves the real remote address stored in the channel attribute.
     * This will be the address parsed from the PROXY protocol header if enabled and successful,
     * otherwise it will be the original channel remote address.
     *
     * @param channel The channel to get the address from.
     * @return The SocketAddress stored in the attribute, or null if not set (should generally not happen
     *         if the ProxyHandler was added, unless accessed too early or removed unexpectedly).
     */
    public static SocketAddress getRealRemoteAddress(Channel channel) {
        return channel.attr(REAL_REMOTE_ADDRESS).get();
    }

    /**
     * Convenience method to get the real remote address as InetSocketAddress.
     * Performs a type check.
     *
     * @param channel The channel to get the address from.
     * @return The InetSocketAddress, or null if the stored address is not an InetSocketAddress or is null.
     */
    @SuppressWarnings("unused")
    public static InetSocketAddress getRealInetRemoteAddress(Channel channel) {
        SocketAddress address = getRealRemoteAddress(channel);
        if (address instanceof InetSocketAddress) {
            return (InetSocketAddress) address;
        }
        return null;
    }

    @SuppressWarnings("unused")
    private void fireRealIpResolvedEvent(ChannelHandlerContext ctx, SocketAddress realAddress) {
        MinecraftForge.EVENT_BUS.post(new RealIpResolvedEvent(ctx.channel(), realAddress, true));
        LOGGER.trace("Fired RealIpResolvedEvent for channel {} with address {}", ctx.channel().id(), realAddress);
    }
}