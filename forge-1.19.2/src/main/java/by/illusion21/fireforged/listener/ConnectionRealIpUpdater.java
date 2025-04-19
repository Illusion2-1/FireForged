package by.illusion21.fireforged.listener;

import by.illusion21.fireforged.Fireforged;
import by.illusion21.fireforged.event.RealIpResolvedEvent;
import by.illusion21.fireforged.mixin.ConnectionAccessor;
import io.netty.channel.Channel;
import net.minecraft.network.Connection;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import org.slf4j.Logger;

import java.net.SocketAddress;

public class ConnectionRealIpUpdater {
    private static final Logger LOGGER = Fireforged.getLogger();

    private static final String MINECRAFT_CONNECTION_HANDLER_NAME = "packet_handler";

    /**
     * Listens for the event indicating the real IP has been resolved.
     * Updates the corresponding net.minecraft.network.Connection instance.
     *
     * @param event The event carrying the channel and resolved address.
     */
    @SubscribeEvent
    public void onRealIpResolved(RealIpResolvedEvent event) {
        Channel channel = event.getChannel();
        SocketAddress realAddress = event.getRealAddress();

        if (channel == null || !channel.isOpen() || realAddress == null) {
            LOGGER.trace("Skipping Connection address update due to invalid channel or address.");
            return;
        }

        channel.eventLoop().execute(() -> {
            try {
                if (!channel.isOpen()) {
                    LOGGER.trace("Channel {} closed before address update could run.", channel.id());
                    return;
                }

                Object handler = channel.pipeline().get(MINECRAFT_CONNECTION_HANDLER_NAME);

                if (handler instanceof Connection connection) {
                    ConnectionAccessor accessor = (ConnectionAccessor) connection;

                    SocketAddress currentAddress = connection.getRemoteAddress();

                    // Only update if the address actually needs changing
                    if (!currentAddress.equals(realAddress)) {
                        LOGGER.debug("Updating Connection address for channel {} from {} to {}", channel.id(), currentAddress, realAddress);
                        // Use the accessor to set the private address field
                        accessor.setAddress(realAddress);
                    } else {
                        LOGGER.trace("Connection address for channel {} already matches real address {}. No update needed.", channel.id(), realAddress);
                    }

                } else if (handler != null) {
                    LOGGER.warn("Pipeline handler '{}' for channel {} is not a Connection. Type: {}",
                            MINECRAFT_CONNECTION_HANDLER_NAME, channel.id(), handler.getClass().getName());
                } else {
                    LOGGER.warn("Could not find Connection handler '{}' in pipeline for channel {} to update address.",
                            MINECRAFT_CONNECTION_HANDLER_NAME, channel.id());
                }
            } catch (Exception e) {
                LOGGER.error("Failed to update Connection address for channel {}", channel.id(), e);
            }
        });
    }

    public static void register() {
        LOGGER.info("\033[1;34mRegistering ConnectionRealIpUpdater listener\033[1;0m");
        MinecraftForge.EVENT_BUS.register(new ConnectionRealIpUpdater());
    }
}