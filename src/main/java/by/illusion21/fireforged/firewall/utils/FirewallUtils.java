package by.illusion21.fireforged.firewall.utils;

import by.illusion21.fireforged.config.entity.Action;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;
import io.netty.util.AttributeKey;

import java.net.SocketAddress;

public class FirewallUtils {

    // Attribute key to store the real IP on the channel after PROXY parsing
    public static final AttributeKey<SocketAddress> REAL_IP_KEY = AttributeKey.valueOf("firewall_real_ip");

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

    public static void closeConnection(ChannelHandlerContext ctx) {
        if (ctx.channel().isActive()) {
            ctx.close();
        }
    }
}