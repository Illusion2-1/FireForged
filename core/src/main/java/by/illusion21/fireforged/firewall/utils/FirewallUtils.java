package by.illusion21.fireforged.firewall.utils;

import by.illusion21.fireforged.config.entity.Action; // Assuming this is acceptable (config POJO/enum)
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;

import java.util.Queue;

public class FirewallUtils {


    /**
     * Closes the connection based on the specified firewall action.
     * REJECT sets SO_LINGER to 0 before closing for an RST packet.
     * DROP closes immediately.
     * ACCEPT is not a valid action here and throws an exception.
     *
     * @param ctx    The channel handler context.
     * @param action The firewall action determining how to close.
     * @throws UnsupportedOperationException if action is ACCEPT.
     */
    public static void closeConnection(ChannelHandlerContext ctx, Action action) {
        if (ctx.channel().isActive()) {
            switch (action) {
                case REJECT -> {
                    ctx.channel().config().setOption(ChannelOption.SO_LINGER, 0);
                    ctx.channel().close();
                }
                case DROP -> ctx.channel().close();
                case ACCEPT -> // wtf, ACCEPT action should have not invoked closeConnection
                        throw new UnsupportedOperationException("ACCEPT action cannot be used to close a connection.");
            }
        }
    }

    /**
     * Closes the connection using a standard close operation.
     * Equivalent to DROP action.
     *
     * @param ctx The channel handler context.
     */
    @SuppressWarnings("unused")
    public static void closeConnection(ChannelHandlerContext ctx) {
        if (ctx != null && ctx.channel().isActive()) {
            ctx.close();
        }
    }

    /**
     * Releases all messages currently in the provided buffer queue.
     * Uses Netty's ReferenceCountUtil to release ReferenceCounted messages.
     * Logs the process and any exceptions during release using the provided logger.
     *
     * @param buffer The queue containing buffered messages (potentially ReferenceCounted).
     * @param logger The logger instance to use for logging messages.
     * @param reason A string indicating why the buffer is being released (for logging).
     */
    public static void releaseBufferedMessages(Queue<Object> buffer, Logger logger, String reason) {
        int count = buffer.size();
        if (count > 0) {
            logger.trace("Releasing {} buffered messages due to: {}", count, reason);
            Object msg;
            while ((msg = buffer.poll()) != null) {
                try {
                    ReferenceCountUtil.release(msg);
                } catch (Exception e) {
                    logger.warn("Exception while releasing buffered message from queue: {}", e.getMessage(), e);
                }
            }
        }
    }
}