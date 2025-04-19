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
        super.handlerAdded(ctx);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        if (this.handlerContext != null) {
            MinecraftForge.EVENT_BUS.unregister(this);
            FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "handlerRemoved");
            this.handlerContext = null;
        } else {
            FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "handlerRemoved (context null)");
        }
        super.handlerRemoved(ctx);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        ctx.fireChannelActive();
    }

    @SubscribeEvent
    public void onRealIpResolved(RealIpResolvedEvent event) {
        if (this.handlerContext == null || event.getChannel() != this.handlerContext.channel()) {
            return;
        }

        this.handlerContext.executor().execute(() -> {
            if (decided || this.handlerContext == null || !this.handlerContext.channel().isOpen()) {
                if (this.handlerContext == null || !this.handlerContext.channel().isOpen() || !firewallAllowed) {
                    FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "onRealIpResolved - skipped/closed/denied");
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
                LOGGER.error("Failed to resolve IP for rule checking: {}", this.resolvedAddress, e);
                decided = true;
                firewallAllowed = false;
                FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "onRealIpResolved - UnknownHostException");
                FirewallUtils.closeConnection(this.handlerContext, Action.DROP); // Drop on error
                return; // Stop processing
            } catch (Exception e) { // Catch potential runtime exceptions from RuleManager
                LOGGER.error("Unexpected error during rule lookup for IP {}: {}", this.resolvedAddress, e.getMessage(), e);
                // Decide before releasing/closing
                decided = true;
                firewallAllowed = false;
                FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "onRealIpResolved - RuleManager Exception");
                FirewallUtils.closeConnection(this.handlerContext, Action.DROP); // Drop on error
                return; // Stop processing
            }

            if (this.handlerContext.pipeline().context(this) == null) {
                LOGGER.warn("FirewallHandler context is gone before action could be taken for channel {}. Releasing buffer.", event.getChannel().id());
                decided = true;
                firewallAllowed = false;
                FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "onRealIpResolved - context gone before action");
                return;
            }
            decided = true;

            if (action != Action.ACCEPT) {
                firewallAllowed = false;
                LOGGER.info("Firewall denied connection from {} (Channel: {}) Action: {}", this.resolvedAddress, event.getChannel().id(), action);
                FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "onRealIpResolved - denied");
                FirewallUtils.closeConnection(this.handlerContext, action);
            } else {
                firewallAllowed = true;
                LOGGER.debug("Firewall allowed connection from {} (Channel: {})", this.resolvedAddress, event.getChannel().id());

                // Drain the buffer BEFORE removing the handler
                drainAndForwardMessages(event.getChannel().id());

                if (this.handlerContext != null && this.handlerContext.pipeline().context(this) != null && this.handlerContext.channel().isOpen()) {
                    try {
                        this.handlerContext.pipeline().remove(this);
                    } catch (Exception e) {
                        LOGGER.error("Error removing FirewallHandler for channel {}: {}", event.getChannel().id(), e.getMessage(), e);
                        FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "onRealIpResolved - removal failed");
                    }
                } else {
                    LOGGER.warn("Context became invalid before handler removal could be attempted for channel {}. Buffer should be clear.", event.getChannel().id());
                    FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "onRealIpResolved - context invalid pre-removal");
                }
            }
        });
    }

    private void drainAndForwardMessages(Object channelId) {
        Object bufferedMsg;
        boolean contextValid = true;

        while ((bufferedMsg = messageBuffer.poll()) != null) {
            if (this.handlerContext != null && this.handlerContext.pipeline().context(this) != null && this.handlerContext.channel().isOpen()) {
                try {
                    this.handlerContext.fireChannelRead(bufferedMsg);
                    // fireChannelRead transfers ownership/reference count, no need to release here
                } catch (Exception e) {
                    LOGGER.error("Exception firing channelRead for buffered message on channel {}: {}", channelId, e.getMessage(), e);
                    ReferenceCountUtil.release(bufferedMsg);
                    FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "onRealIpResolved - exception during drain");
                    contextValid = false;
                    break;
                }
            } else {
                LOGGER.warn("Context became invalid while draining buffer for channel {}. Releasing remaining messages.", channelId);
                ReferenceCountUtil.release(bufferedMsg); // Release the current message
                // Release the rest using the utility method
                FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "onRealIpResolved - context invalid during drain");
                contextValid = false;
                break; // Stop draining
            }
        }
        if (!contextValid) {
            FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "onRealIpResolved - post-drain cleanup after invalid context");
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (decided && firewallAllowed) {
            if (ctx.pipeline().context(this) != null) {
                LOGGER.trace("FirewallHandler forwarding read post-allow decision for channel {}.", ctx.channel().id());
            }
            ctx.fireChannelRead(msg);
            return;
        }

        if (decided) {
            LOGGER.trace("FirewallHandler discarding message for denied/closing channel {}", ctx.channel().id());
            ReferenceCountUtil.release(msg);
            return;
        }

        LOGGER.trace("FirewallHandler buffering message for channel {} until firewall decision. Buffer size: {}", ctx.channel().id(), messageBuffer.size() + 1);
        messageBuffer.offer(ReferenceCountUtil.retain(msg));
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        LOGGER.error("Exception in FirewallHandler pipeline for channel {}: {}",
                (ctx != null && ctx.channel() != null) ? ctx.channel().id() : "unknown",
                cause.getMessage(), cause);

        FirewallUtils.releaseBufferedMessages(this.messageBuffer, LOGGER, "exceptionCaught");

        if (!decided) {
            decided = true;
            firewallAllowed = false;
            safeUnregisterFromEventBus();
            if (ctx != null && ctx.channel().isOpen()) {
                FirewallUtils.closeConnection(ctx, Action.DROP);
            }
        } else if (ctx != null && ctx.pipeline().context(this) != null) {
            LOGGER.trace("Forwarding exception caught after firewall decision for channel {}", ctx.channel().id());
            ctx.fireExceptionCaught(cause);
            safeUnregisterFromEventBus();
        } else {
            safeUnregisterFromEventBus();
        }
    }

    private void safeUnregisterFromEventBus() {
        Object channelId = (this.handlerContext != null && this.handlerContext.channel() != null)
                ? this.handlerContext.channel().id()
                : "unknown";
        try {
            MinecraftForge.EVENT_BUS.unregister(this);
            LOGGER.trace("Attempted safe unregister from event bus for channel {}", channelId);
        } catch (Exception e) {
            LOGGER.error("Exception during safe unregister from event bus for channel {}: {}", channelId, e.getMessage(), e);
        }
    }

    @SuppressWarnings("unused")
    public boolean isCheckPerformed() {
        return checkPerformed;
    }
}