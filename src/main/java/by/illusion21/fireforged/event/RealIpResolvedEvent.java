package by.illusion21.fireforged.event;


import io.netty.channel.Channel;
import net.minecraftforge.eventbus.api.Event;

import java.net.SocketAddress;

/**
 * Fired by ProxyHandler when the real client address has been determined
 * (either parsed from PROXY protocol or using the original address if disabled).
 */
public class RealIpResolvedEvent extends Event {
    private final Channel channel;
    private final SocketAddress realAddress;
    private final boolean proxyProtocolUsed; // Flag to indicate if the address came from PROXY header

    public RealIpResolvedEvent(Channel channel, SocketAddress realAddress, boolean proxyProtocolUsed) {
        this.channel = channel;
        this.realAddress = realAddress;
        this.proxyProtocolUsed = proxyProtocolUsed;
    }

    /**
     * @return The channel associated with this resolved address.
     */
    public Channel getChannel() {
        return channel;
    }

    /**
     * @return The resolved real remote address.
     */
    public SocketAddress getRealAddress() {
        return realAddress;
    }

    /**
     * @return True if the address was obtained via the PROXY protocol,
     *         false if it's the original address because the protocol was disabled.
     */
    @SuppressWarnings("unused")
    public boolean isProxyProtocolUsed() {
        return proxyProtocolUsed;
    }
}