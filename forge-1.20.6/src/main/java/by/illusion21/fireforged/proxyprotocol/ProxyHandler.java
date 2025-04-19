package by.illusion21.fireforged.proxyprotocol;

// FIXME: Decoupling proxy parser into a dedicated pipeline handler had yielded more timing synchronization issues and mitigations that may affect performance thus have been taken, which, not best suits what i desired, introduced a more complex structure. I hope that it won't produce any strange exceptions, so that i don't have to make further mitigations. And hopefully it doesn't cause large impact to performance.

import by.illusion21.fireforged.Fireforged;
import by.illusion21.fireforged.config.FirewallConfig;
import by.illusion21.fireforged.event.RealIpResolvedEvent;
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

public class ProxyHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOGGER = Fireforged.getLogger();

    public static final AttributeKey<SocketAddress> REAL_REMOTE_ADDRESS = AttributeKey.newInstance("realRemoteAddress");

    private ProxyProtocolProcessor protocolProcessor;
    private boolean proxyProtocolEnabled;

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        this.proxyProtocolEnabled = FirewallConfig.isProxyProtocolEnabled.get();
        SocketAddress originalAddress = ctx.channel().remoteAddress();

        if (!proxyProtocolEnabled) {
            ctx.channel().attr(REAL_REMOTE_ADDRESS).set(originalAddress);
            ctx.pipeline().remove(this);
        } else {
            LOGGER.debug("[{}] Proxy protocol enabled for {}. Waiting for header.", ctx.channel().id(), originalAddress);
            this.protocolProcessor = new ProxyProtocolProcessor(LOGGER, originalAddress);
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (!proxyProtocolEnabled || (protocolProcessor != null && protocolProcessor.isProcessingComplete())) {
            ctx.fireChannelRead(msg);
            return;
        }

        if (protocolProcessor == null) {
            LOGGER.error("[{}] Protocol enabled but processor is null unexpectedly for channel", ctx.channel().id());
            handleProcessingFailure(ctx, "Internal state error: processor null");
            ReferenceCountUtil.release(msg);
            return;
        }

        if (!(msg instanceof ByteBuf data)) {
            LOGGER.warn("[{}] Received non-ByteBuf message before PROXY header parsed from {}. Message type: {}",
                    ctx.channel().id(), ctx.channel().remoteAddress(), msg.getClass().getName());
            handleProcessingFailure(ctx, "Received non-ByteBuf before header");
            ReferenceCountUtil.release(msg);
            return;
        }

        // Delegate processing to the common processor
        ProxyProtocolProcessor.ProcessingResult result = null;
        try {
            result = protocolProcessor.processData(ctx.alloc(), data);

            switch (result.getStatus()) {
                case SUCCESS:
                    handleProcessingSuccess(ctx, result.getRealAddress(), result.getRemainingData());
                    break;
                case FAILURE:
                    handleProcessingFailure(ctx, result.getFailureReason());
                    break;
                case INCOMPLETE:
                    LOGGER.trace("[{}] Proxy header processing incomplete, waiting for more data.", ctx.channel().id());
                    break;
            }
        } catch (Exception e) {
            LOGGER.error("[{}] Unexpected exception during proxy processing for {}", ctx.channel().id(), ctx.channel().remoteAddress(), e);
            handleProcessingFailure(ctx, "Unexpected exception: " + e.getMessage());
        } finally {
            if (!(result != null && result.getStatus() == ProxyProtocolProcessor.ProcessingResult.Status.SUCCESS && result.getRemainingData() == data)) {
                ReferenceCountUtil.release(data);
            }
        }
    }

    private void handleProcessingSuccess(ChannelHandlerContext ctx, SocketAddress realAddress, ByteBuf remainingData) {
        LOGGER.info("[{}] PROXY protocol parsed successfully for {}. Real client: {}", ctx.channel().id(), ctx.channel().remoteAddress(), realAddress);

        ctx.channel().attr(REAL_REMOTE_ADDRESS).set(realAddress);
        fireRealIpResolvedEvent(ctx, realAddress);

        if (remainingData != null && remainingData.isReadable()) {
            LOGGER.trace("[{}] Forwarding {} bytes of remaining data after PROXY header.", ctx.channel().id(), remainingData.readableBytes());
            ctx.fireChannelRead(remainingData); // Pass ownership downstream
        } else {
            if (remainingData != null) ReferenceCountUtil.release(remainingData); // Release if empty/null
            LOGGER.trace("[{}] No remaining data after PROXY header.", ctx.channel().id());
        }


        releaseProcessorAndRemoveHandler(ctx);
    }

    private void handleProcessingFailure(ChannelHandlerContext ctx, String reason) {
        LOGGER.warn("[{}] Invalid PROXY header processing from {}: {}. Closing connection.", ctx.channel().id(), ctx.channel().remoteAddress(), reason);
        ctx.close();
        releaseProcessorAndRemoveHandler(ctx);
    }

    private void releaseProcessorAndRemoveHandler(ChannelHandlerContext ctx) {
        if (protocolProcessor != null) {
            protocolProcessor.releaseResources();
            protocolProcessor = null; // Allow GC
        }
        // Remove self from pipeline if still present
        if (ctx.pipeline().context(this) != null) {
            ctx.pipeline().remove(this);
            LOGGER.trace("[{}] ProxyHandler removed from pipeline.", ctx.channel().id());
        }
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        if (protocolProcessor != null) {
            LOGGER.trace("[{}] Releasing processor resources in handlerRemoved.", ctx.channel().id());
            protocolProcessor.releaseResources();
            protocolProcessor = null;
        }
        LOGGER.trace("[{}] ProxyHandler fully removed callback.", ctx.channel().id());
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        LOGGER.error("[{}] Exception in ProxyHandler for channel {}: {}", ctx.channel().id(), ctx.channel().remoteAddress(), cause.getMessage(), cause);
        releaseProcessorAndRemoveHandler(ctx);
        ctx.close();
    }
    public static SocketAddress getRealRemoteAddress(Channel channel) {
        return channel.attr(REAL_REMOTE_ADDRESS).get();
    }

    @SuppressWarnings("unused")
    public static InetSocketAddress getRealInetRemoteAddress(Channel channel) {
        SocketAddress address = getRealRemoteAddress(channel);
        if (address instanceof InetSocketAddress) {
            return (InetSocketAddress) address;
        }
        return null;
    }

    private void fireRealIpResolvedEvent(ChannelHandlerContext ctx, SocketAddress realAddress) {
        try {
            MinecraftForge.EVENT_BUS.post(new RealIpResolvedEvent(ctx.channel(), realAddress, true));
            LOGGER.trace("[{}] Fired RealIpResolvedEvent for channel with address {}", ctx.channel().id(), realAddress);
        } catch (Exception e) {
            LOGGER.error("[{}] Failed to post RealIpResolvedEvent", ctx.channel().id(), e);
        }
    }
}