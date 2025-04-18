package by.illusion21.fireforged.firewall.utils;

import by.illusion21.fireforged.config.entity.Action;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;

public class FirewallUtils {

    // --- Connection Closing ---
    public static void closeConnection(ChannelHandlerContext ctx, Action action) {
        if (ctx.channel().isActive()) {
            switch (action) {
                case REJECT -> {
                    ctx.channel().config().setOption(ChannelOption.SO_LINGER, 0);
                    ctx.channel().close();
                }
                case DROP -> ctx.channel().close();
                case ACCEPT -> // wtf, ACCEPT action should have not invoked closeConnection
                        throw new UnsupportedOperationException("ACCEPT cannot be used for closed connection.");
            }
        }
    }

    @SuppressWarnings("unused")
    public static void closeConnection(ChannelHandlerContext ctx) {
        if (ctx.channel().isActive()) {
            ctx.close();
        }
    }
}