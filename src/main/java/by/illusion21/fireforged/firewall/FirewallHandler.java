package by.illusion21.fireforged.firewall;

import by.illusion21.fireforged.Fireforged;
import by.illusion21.fireforged.config.entity.Action;
import by.illusion21.fireforged.event.RealIpResolvedEvent;
import by.illusion21.fireforged.firewall.utils.FirewallUtils;
import by.illusion21.fireforged.firewall.utils.RuleManager;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import org.slf4j.Logger;

import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayDeque;
import java.util.Queue;

public class FirewallHandler extends ChannelInboundHandlerAdapter {

    private static final Logger LOGGER = Fireforged.getLogger();
    private static final RuleManager RULE_MANAGER = Fireforged.getRuleManager();

    // Buffer to hold messages received before the firewall decision
    private final Queue<Object> messageBuffer = new ArrayDeque<>();

    private boolean checkPerformed = false;
    private ChannelHandlerContext handlerContext;
    private SocketAddress resolvedAddress = null;
    private boolean decided = false;
    private boolean firewallAllowed = false;

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        this.handlerContext = ctx;
        MinecraftForge.EVENT_BUS.register(this);
        LOGGER.trace("FirewallHandler added and registered for event bus for channel {}", ctx.channel().id());
        super.handlerAdded(ctx);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        MinecraftForge.EVENT_BUS.unregister(this);
        LOGGER.trace("FirewallHandler removed and unregistered from event bus for channel {}", ctx.channel().id());
        releaseBuffer("handlerRemoved");
        this.handlerContext = null;
        super.handlerRemoved(ctx);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        LOGGER.trace("FirewallHandler received channelActive for {}. Allowing downstream initialization. Firewall check deferred.", ctx.channel().remoteAddress());
        ctx.fireChannelActive();
    }

    @SubscribeEvent
    public void onRealIpResolved(RealIpResolvedEvent event) {
        if (this.handlerContext == null || event.getChannel() != this.handlerContext.channel()) {
            return;
        }

        this.handlerContext.executor().execute(() -> {
            if (decided || this.handlerContext == null || !this.handlerContext.channel().isOpen()) {
                LOGGER.trace("Firewall check skipped for channel {} as it was already decided or channel is closed/handler removed.", event.getChannel().id());
                if (this.handlerContext == null || !this.handlerContext.channel().isOpen()) {
                    releaseBuffer("onRealIpResolved - skipped/closed");
                }
                return;
            }

            checkPerformed = true;
            this.resolvedAddress = event.getRealAddress();
            LOGGER.debug("Firewall checking connection for channel {} with resolved address: {}", event.getChannel().id(), this.resolvedAddress);
            final Action action;
            try {
                action = RULE_MANAGER.getActionForIp(this.resolvedAddress);
            } catch (UnknownHostException e) {
                throw new RuntimeException(e);
            }

            if (this.handlerContext.pipeline().context(this) == null) {
                LOGGER.warn("FirewallHandler context is gone before action could be taken for channel {}. Releasing buffer.", event.getChannel().id());
                decided = true;
                releaseBuffer("onRealIpResolved - context gone");
                return;
            }

            decided = true;

            if (action != Action.ACCEPT) {
                firewallAllowed = false;
                LOGGER.info("Firewall denied connection from {} (Channel: {}) Action: {}", this.resolvedAddress, event.getChannel().id(), action);
                releaseBuffer("onRealIpResolved - denied");
                FirewallUtils.closeConnection(this.handlerContext, action);
            } else {
                firewallAllowed = true;
                LOGGER.debug("Firewall allowed connection from {} (Channel: {})", this.resolvedAddress, event.getChannel().id());

                // Drain the buffer BEFORE removing the handler
                LOGGER.trace("Draining {} buffered messages for channel {}", messageBuffer.size(), event.getChannel().id());
                Object bufferedMsg;
                boolean contextValid = true;
                while ((bufferedMsg = messageBuffer.poll()) != null) {
                    if (this.handlerContext != null && this.handlerContext.pipeline().context(this) != null && this.handlerContext.channel().isOpen()) {
                        this.handlerContext.fireChannelRead(bufferedMsg);
                    } else {
                        LOGGER.warn("Context became invalid while draining buffer for channel {}. Releasing remaining messages.", event.getChannel().id());
                        ReferenceCountUtil.release(bufferedMsg);
                        releaseBuffer("onRealIpResolved - context invalid during drain");
                        contextValid = false;
                        break; // Stop draining
                    }
                }

                // Remove the handler only if context is still valid after draining
                if (contextValid && this.handlerContext != null && this.handlerContext.pipeline().context(this) != null) {
                    LOGGER.trace("Removing FirewallHandler after allowing and draining buffer for channel {}", event.getChannel().id());
                    this.handlerContext.pipeline().remove(this);
                } else if (contextValid) {
                    LOGGER.warn("Context became invalid just before handler removal for channel {}", event.getChannel().id());
                }
            }
        });
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        // If firewall decision is made and connection is allowed, forward directly.
        // This handles messages arriving after the allow decision but before handler removal is complete.
        if (decided && firewallAllowed) {
            if (ctx.pipeline().context(this) != null) {
                LOGGER.trace("FirewallHandler forwarding read post-allow decision for channel {}.", ctx.channel().id());
            } else {
                LOGGER.warn("FirewallHandler.channelRead called after removal for channel {}.", ctx.channel().id());
            }
            ctx.fireChannelRead(msg);
            return;
        }

        // If decision is made, and it was denied, channel is closing. Discard message.
        if (decided) {
            LOGGER.trace("FirewallHandler discarding message for denied/closing channel {}", ctx.channel().id());
            ReferenceCountUtil.release(msg); // Must release the message!
            return;
        }

        LOGGER.trace("FirewallHandler buffering message for channel {} until firewall decision. Buffer size: {}", ctx.channel().id(), messageBuffer.size() + 1);
        messageBuffer.offer(ReferenceCountUtil.retain(msg));
        // Do NOT forward the message down the pipeline yet (ctx.fireChannelRead is not called)
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        LOGGER.error("Exception in FirewallHandler for channel {}: {}",
                (ctx != null && ctx.channel() != null) ? ctx.channel().id() : "unknown",
                cause.getMessage(), cause);

        releaseBuffer("exceptionCaught");

        if (!decided) {
            MinecraftForge.EVENT_BUS.unregister(this);
            if (ctx != null && ctx.channel().isOpen()) {
                ctx.close();
            }
        } else if (ctx != null && ctx.pipeline().context(this) != null) {
            // If exception happens AFTER decision (likely ALLOW), propagate it
            // so downstream handlers know something went wrong.
            ctx.fireExceptionCaught(cause);
        }
        decided = true; // Mark decided on error
    }

    /**
     * Helper method to release all messages currently in the buffer.
     *
     * @param reason A string indicating why the buffer is being released (for logging).
     */
    private void releaseBuffer(String reason) {
        int count = messageBuffer.size();
        if (count > 0) {
            LOGGER.trace("Releasing {} buffered messages due to: {}", count, reason);
            Object msg;
            while ((msg = messageBuffer.poll()) != null) {
                try {
                    ReferenceCountUtil.release(msg);
                } catch (Exception e) {
                    LOGGER.warn("Exception while releasing buffered message: {}", e.getMessage(), e);
                }
            }
        }
    }

    @SuppressWarnings("unused")
    public boolean isCheckPerformed() {
        return checkPerformed;
    }
}