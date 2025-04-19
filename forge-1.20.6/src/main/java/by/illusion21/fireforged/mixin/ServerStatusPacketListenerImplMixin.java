package by.illusion21.fireforged.mixin;

import by.illusion21.fireforged.Fireforged;
import by.illusion21.fireforged.config.FirewallConfig;
import io.netty.channel.ChannelOption;
import net.minecraft.network.Connection;
import net.minecraft.network.protocol.ping.ServerboundPingRequestPacket;
import net.minecraft.network.protocol.status.ServerboundStatusRequestPacket;
import net.minecraft.server.network.ServerStatusPacketListenerImpl;
import org.slf4j.Logger;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;


@Mixin(ServerStatusPacketListenerImpl.class)
public abstract class ServerStatusPacketListenerImplMixin {

    @Unique
    private static final Logger fireforged$logger = Fireforged.getLogger();

    @Shadow @Final private Connection connection;

    static {
        if (FirewallConfig.hideMotd.get()) fireforged$logger.info("\033[1;36mHide Motd function enable. Clients will no longer be able to ping server.\033[0m");
    }

    @Inject(method = "handleStatusRequest", at = @At("HEAD"), cancellable = true)
    private void preventStatusResponse(ServerboundStatusRequestPacket p_10095_, CallbackInfo ci) {
        if (FirewallConfig.hideMotd.get()) {
            // If hiding is enabled, simply cancel the method.
            // No response packet will be sent, and the connection remains open
            // until potentially timed out by the client or server.
            // This avoids sending any data back for the status request.
            fireforged$logger.info("Initial status probe [{}], dropping", this.connection.getRemoteAddress());
            this.connection.channel().config().setOption(ChannelOption.SO_LINGER, 0);
            this.connection.channel().close();
            ci.cancel();
        }
    }

    @Inject(method = "handlePingRequest", at = @At("HEAD"), cancellable = true)
    private void preventPingResponse(ServerboundPingRequestPacket p_10093_, CallbackInfo ci) {
        if (FirewallConfig.hideMotd.get()) {
            // If hiding is enabled, disconnect the client immediately
            // without sending the pong packet.
            // Use the same disconnect reason the original method uses after sending pong.
            fireforged$logger.info("Initial ping [{}], dropping", this.connection.getRemoteAddress());
            this.connection.channel().config().setOption(ChannelOption.SO_LINGER, 0);
            this.connection.channel().close();
            // Cancel the original method to prevent the pong packet and the original disconnect call.
            ci.cancel();
        }


        // If not hiding, the original method continues execution normally.
    }
}