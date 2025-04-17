package by.illusion21.fireforged.firewall.utils;


import by.illusion21.fireforged.config.entity.Action;
import by.illusion21.fireforged.config.entity.FirewallRules;
import by.illusion21.fireforged.config.entity.Rule;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.net.SocketAddress;
import java.net.InetSocketAddress;

public class RuleManager {

    private final FirewallRules firewallRules;

    /**
     * Constructs a RuleManager and initializes firewall rules from a configuration string.
     * Rules within the string are separated by commas.
     * Each rule segment should be in the format: "CIDR ACTION PRIORITY".
     * Example: "0.0.0.0/0 ACCEPT 65535, ::/0 ACCEPT 65535, 139.242.12.23/32 REJECT 1"
     *
     * @param rulesConfig The string containing comma-separated firewall rule definitions.
     * @throws IllegalArgumentException if the config string is malformed or contains invalid rule data.
     */
    public RuleManager(String rulesConfig) {
        this.firewallRules = new FirewallRules();
        Objects.requireNonNull(rulesConfig, "Rules configuration string cannot be null");

        Arrays.stream(rulesConfig.split(","))
            .map(String::trim)
            .filter(segment -> !segment.isEmpty() && !segment.startsWith("#"))
            .forEach(trimmedSegment -> {
                String[] parts = trimmedSegment.split("\\s+");
                if (parts.length != 3) {
                    throw new IllegalArgumentException("Malformed rule segment (expected 3 parts: CIDR ACTION PRIORITY): '" + trimmedSegment + "'");
                }
                 try {
                    Action action = Action.valueOf(parts[1].toUpperCase());
                    int priority = Integer.parseInt(parts[2]);
                    Rule rule = new Rule(parts[0], action, priority);
                    firewallRules.addRule(rule);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Invalid rule data in segment: '" + trimmedSegment + "'", e);
                }
            });
    }


    /**
     * Determines the appropriate firewall action for a given IP address.
     * It iterates through the sorted rules (highest priority, most specific CIDR first)
     * and returns the action of the first matching rule.
     *
     * @param ipAddress The IP address (IPv4 or IPv6) to check, without CIDR notation.
     * @return The Action (ACCEPT, REJECT, DROP) determined by the matching rule.
     * @throws UnknownHostException if the provided ipAddress string is not a valid IP address.
     * @throws IllegalStateException if no matching rule is found (should not happen with default rules).
     */
    public Action getActionForIp(String ipAddress) throws UnknownHostException {
        InetAddress targetIp = InetAddress.getByName(ipAddress);
        byte[] targetIpBytes = targetIp.getAddress();

        List<Rule> sortedRules = firewallRules.getSortedRules();

        for (Rule rule : sortedRules) {
            if (matches(targetIpBytes, rule)) {
                return rule.getAction();
            }
        }

        // This should ideally not be reached if default rules (0.0.0.0/0 or ::/0) exist
        throw new IllegalStateException("No matching firewall rule found for IP: " + ipAddress + ". Check configuration for default rules.");
    }


    /**
     * Determines the appropriate firewall action for a given SocketAddress.
     * Extracts the IP address from the SocketAddress and delegates to the String version.
     *
     * @param socketAddress The SocketAddress to check.
     * @return The Action (ACCEPT, REJECT, DROP) determined by the matching rule.
     * @throws UnknownHostException if the IP address from the SocketAddress is not valid.
     * @throws IllegalStateException if no matching rule is found.
     * @throws IllegalArgumentException if the provided SocketAddress is not an InetSocketAddress.
     */
    public Action getActionForIp(SocketAddress socketAddress) throws UnknownHostException {
        if (!(socketAddress instanceof InetSocketAddress inetSocketAddress)) {
            throw new IllegalArgumentException("Only InetSocketAddress is supported, got: " +
                    socketAddress.getClass().getName());
        }

        InetAddress inetAddress = inetSocketAddress.getAddress();

        // If the SocketAddress was created with an unresolved host name, getAddress() might return null
        if (inetAddress == null) {
            throw new UnknownHostException("Could not resolve host in SocketAddress: " + socketAddress);
        }

        return getActionForIp(inetAddress.getHostAddress());
    }

    /**
     * Checks if a target IP address matches a rule's CIDR block.
     * Handles both IPv4 and IPv6.
     *
     * @param targetIpBytes The byte array representation of the IP to check.
     * @param rule          The rule containing the CIDR to match against.
     * @return true if the IP matches the rule's CIDR, false otherwise.
     */
    private boolean matches(byte[] targetIpBytes, Rule rule) {
        String cidr = rule.getCidr();
        int prefixLength = rule.getPrefixLength();

        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            System.err.println("Warning: Skipping rule with malformed CIDR in matching logic: " + cidr);
            return false;
        }

        InetAddress ruleNetworkAddress;
        try {
            ruleNetworkAddress = InetAddress.getByName(parts[0]);
        } catch (UnknownHostException e) {
            System.err.println("Warning: Skipping rule with unresolvable network address: " + parts[0]);
            return false;
        }

        byte[] ruleNetworkBytes = ruleNetworkAddress.getAddress();

        if (targetIpBytes.length != ruleNetworkBytes.length) {
            return false;
        }

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++) {
            if (targetIpBytes[i] != ruleNetworkBytes[i]) {
                return false;
            }
        }

        if (remainingBits > 0) {
            int mask = (0xFF << (8 - remainingBits)) & 0xFF;
            return (targetIpBytes[fullBytes] & mask) == (ruleNetworkBytes[fullBytes] & mask);
        }

        return true;
    }

    public FirewallRules getFirewallRules() {
        return firewallRules;
    }

    // --- 测试用例 ---
    public static void main(String[] args) {
        String config = "0.0.0.0/0 ACCEPT 65535, ::/0 ACCEPT 65535 , 192.168.1.0/24 REJECT 100,10.0.0.0/8 DROP 200 ,  192.168.1.10/32 ACCEPT 10 ,139.242.12.23/32 REJECT 1, 2001:db8:abcd:0012::0/64 DROP 50, 2001:db8:abcd:0012::53/128 ACCEPT 5";

        System.out.println("Parsing config: " + config);
        try {
            RuleManager manager = new RuleManager(config);

            String[] testIPs = {
                    "192.168.1.10",   // ACCEPT 10
                    "192.168.1.50",   // REJECT 100
                    "10.1.2.3",       // DROP 200
                    "139.242.12.23",  // REJECT 1
                    "8.8.8.8",        // ACCEPT 65535 (IPv4 default)
                    "2001:db8:abcd:0012::53", // ACCEPT 5
                    "2001:db8:abcd:0012::ff", // DROP 50
                    "2001:db8:ffff::1", // ACCEPT 65535 (IPv6 default)
                    "192.168.2.1"     // ACCEPT 65535 (IPv4 default)
            };

            for (String ip : testIPs) {
                try {
                    Action action = manager.getActionForIp(ip);
                    System.out.println("IP: " + ip + " -> Action: " + action);
                } catch (UnknownHostException e) {
                    System.err.println("Invalid IP format: " + ip);
                } catch (IllegalStateException e) {
                    System.err.println("Error processing IP " + ip + ": " + e.getMessage());
                }
            }

            System.out.println("\nSorted Rules internal view:");
            manager.firewallRules.getSortedRules().forEach(r ->
                    System.out.printf("  Priority: %-5d Prefix: %-3d CIDR: %-25s Action: %s%n", // Adjusted padding for IPv6
                            r.getPriority(), r.getPrefixLength(), r.getCidr(), r.getAction())
            );

        } catch (IllegalArgumentException e) {
            System.err.println("Error initializing RuleManager: " + e.getMessage());
        }
    }
}