package by.illusion21.fireforged.mixin;

import by.illusion21.fireforged.Fireforged;
import by.illusion21.fireforged.proxyprotocol.ProxyHandler;
import io.netty.channel.Channel;
import io.netty.channel.ChannelPipeline;
import org.slf4j.Logger;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;
import by.illusion21.fireforged.firewall.FirewallHandler;


@Mixin(targets = "net.minecraft.server.network.ServerConnectionListener$1") // into the very first initChannel
public abstract class ServerConnectionListenerInitializerMixin {
    @Unique
    private static final Logger fireforged$LOGGER = Fireforged.getLogger();

    static {
        fireforged$LOGGER.info("\033[1;36m\033[4mMixining into [{}]\033[0m", ServerConnectionListenerInitializerMixin.class.getName());
        fireforged$LOGGER.info("\033[1;36mfireforged_firewall_handler \033[1;33mwill be taking over input chain from now on\033[0m");
    }
    @Inject(method = "initChannel(Lio/netty/channel/Channel;)V", at = @At("HEAD"))
    private void onInitChannelAddFirewall(Channel channel, CallbackInfo ci) {
        ChannelPipeline pipeline = channel.pipeline();

        if (pipeline.get("fireforged_firewall_handler") == null) { // safety check
            pipeline.addFirst("fireforged_proxy_handler", new ProxyHandler());
            pipeline.addLast("fireforged_firewall_handler", new FirewallHandler());
            fireforged$LOGGER.debug("Added FirewallHandler for channel: {}", channel.id());
        }
    }
}