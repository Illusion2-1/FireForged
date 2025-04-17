package by.illusion21.fireforged.config.entity;

// single firewall rule object
public class Rule {
    private final String cidr;
    private final Action action;
    private final int priority;
    private final int prefixLength; // prefix length for sorting

    public Rule(String cidr, Action action, int priority) {
        this.cidr = cidr;
        this.action = action;
        this.priority = priority;
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid CIDR: " + cidr);
        }
        this.prefixLength = Integer.parseInt(parts[1]);
    }

    // Getters
    public String getCidr() { return cidr; }
    public Action getAction() { return action; }
    public int getPriority() { return priority; }
    public int getPrefixLength() { return prefixLength; }
}

