package by.illusion21.fireforged;

import by.illusion21.fireforged.config.FirewallConfig;
import by.illusion21.fireforged.firewall.utils.RuleManager;
import by.illusion21.fireforged.listener.ConnectionRealIpUpdater;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.eventbus.api.IEventBus;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.config.ModConfig;
import net.minecraftforge.fml.event.lifecycle.FMLCommonSetupEvent;
import net.minecraftforge.event.server.ServerStartingEvent;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Mod(Fireforged.MODID)
public class Fireforged {
    public static final String MODID = "fireforged";

    // have it some fancy colour yeaaaaaaaaaaaaaaaah
    private static final Logger LOGGER = LoggerFactory.getLogger("\033[1;33mFireForged\033[0;32m");

    private static RuleManager RULE_MANAGER = null;

    public Fireforged(FMLJavaModLoadingContext context) {
        IEventBus modEventBus = context.getModEventBus();
        context.registerConfig(ModConfig.Type.SERVER, FirewallConfig.SERVER_CONFIG);
        modEventBus.addListener(this::commonSetup);

        MinecraftForge.EVENT_BUS.register(this);
    }

    public static RuleManager getRuleManager() {
        return RULE_MANAGER;
    }

    private void commonSetup(final FMLCommonSetupEvent event) {
        LOGGER.info("\033[1;34m\033[5mThe \033[36mFireForged\033[32m initializating. \033[0m");
        event.enqueueWork(ConnectionRealIpUpdater::register);
        LOGGER.info("\033[1;34mInitialized Proxy Protocol ip updater\033[0m");
    }

    @SubscribeEvent
    public void onServerStarting(ServerStartingEvent event) {
        RULE_MANAGER = new RuleManager(FirewallConfig.rules.get());
        LOGGER.info("\033[1;34mInitialized firewall rule manager\033[0m");
        LOGGER.info("\033[1;34mLoaded rules:\033[0m");
        RULE_MANAGER.getFirewallRules().getSortedRules().forEach(rule -> {
            String logMessage = String.format(
                    // {Priority}  {CIDR}          /{Prefix}  {Action}
                    "\033[0m%-5s  \033[1;34m%-22s \033[32m/%-3s  \033[0m%-7s",
                    rule.getPriority(),      // Field 1: Priority, normal color, 5 chars wide, left-aligned
                    rule.getCidr(),          // Field 2: CIDR, blue color, 22 chars wide, left-aligned
                    rule.getPrefixLength(),  // Field 3: Prefix Length, green color, prefixed with '/', 3 chars wide, left-aligned
                    rule.getAction()         // Field 4: Action, normal color, 7 chars wide, left-aligned
            );
            LOGGER.info(logMessage);
        });
    }


    public static Logger getLogger(){
        return LOGGER;
    }
}
