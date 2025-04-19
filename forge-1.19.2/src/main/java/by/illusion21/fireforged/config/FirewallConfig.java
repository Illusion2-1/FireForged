package by.illusion21.fireforged.config;

import net.minecraftforge.common.ForgeConfigSpec;

public class FirewallConfig {
    public static ForgeConfigSpec SERVER_CONFIG;
    public static ForgeConfigSpec.BooleanValue isProxyProtocolEnabled;
    public static ForgeConfigSpec.BooleanValue hideMotd;
    public  static ForgeConfigSpec.ConfigValue<String> rules;

    static {
        ForgeConfigSpec.Builder server_builder = new ForgeConfigSpec.Builder();
        server_builder.push("config");
        isProxyProtocolEnabled = server_builder.comment("""
                Defines whether proxy protocol is enabled.
                If you are using a direct connect, DO NOT enable this
                ------------------------------------
                If you are using frp port-forwarding, enable this to make certain firewall gets the real ip of players
                AND SET proxy_protocol_version IN FRPC TO V2!!!(MUST)
                ABOUT how to set proxy_protocol_version, refer to official document""").define("ProxyProtocol", false);

        hideMotd = server_builder.comment("\nhides motd to whoever attempted to scan").define("hideMotd", false);

        rules = server_builder.comment("""
                
                Please edit your rules with the
                [ip/cidr] [action] [priority]
                syntax, separating rules with commas (,)
                Supported actions are: REJECT, DROP, ACCEPT.
                \t- ACCEPT: allow the CIDR; by setting 0.0.0.0/0 ACCEPT 65535 rule, you change the default behavior of fireforged to accept CIDRs that are not in the block list
                \t- REJECT: sends RST after the remote tries 3 packets handshake
                \t- DROP: sends FIN after the remote tries 3 packets handshake
                PRIORITY ranges from 0 (highest) to 65535 (lowest)
                DUE TO LAYER 7 LIMITATION, WE WERE UNABLE TO INTERCEPT IN EARLY SYN HANDSHAKE STAGE
                ------------------------------------
                example blocks 139.242.12.23 while accepting others:
                0.0.0.0/0 ACCEPT 65535, ::/0 ACCEPT 65535, 139.242.12.23/32 REJECT 1""").define("FilterRules", "0.0.0.0/0 ACCEPT 65535, ::/0 ACCEPT 65535");

        server_builder.pop();
        SERVER_CONFIG = server_builder.build();
    }
}
