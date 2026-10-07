package model;

import java.util.ArrayList;
import java.util.List;

public class PersistenceEntry {

    private final PersistenceType type;
    private final String name;
    private final String path;
    private final String command;
    private final String location;

    private int riskScore;
    private RiskLevel riskLevel;

    private final List<String> reasons = new ArrayList<>();

    public PersistenceEntry(
            PersistenceType type,
            String name,
            String path,
            String command,
            String location
    ) {
        this.type = type;
        this.name = name;
        this.path = path;
        this.command = command;
        this.location = location;
    }

    public PersistenceType getType() {
        return type;
    }

    public String getName() {
        return name;
    }

    public String getPath() {
        return path;
    }

    public String getCommand() {
        return command;
    }

    public String getLocation() {
        return location;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }

    public List<String> getReasons() {
        return reasons;
    }

    public void addReason(String reason) {
        reasons.add(reason);
    }
}