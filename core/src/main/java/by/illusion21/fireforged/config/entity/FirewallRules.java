package by.illusion21.fireforged.config.entity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class FirewallRules {
    private final CopyOnWriteArrayList<Rule> rules = new CopyOnWriteArrayList<>();
    public void addRule(Rule rule) {
        rules.add(rule);
        /*
        * Descends by priority, prefix length
        * prefer higher priority and more concrete cidr range
        * */
        rules.sort(Comparator
                .comparingInt(Rule::getPriority).reversed()
                .thenComparingInt(Rule::getPrefixLength).reversed()
        );
    }

    public List<Rule> getSortedRules() {
        return new ArrayList<>(rules); // return the copy
    }
}
