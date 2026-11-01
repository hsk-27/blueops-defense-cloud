package com.blueops.reporting;

import java.util.List;
import java.util.Map;

public class SocOverviewMetricsDto {
    private long totalIncidents;
    private long activeIncidents;
    private long criticalIncidents;
    private long highIncidents;
    private long mediumIncidents;
    private long lowIncidents;

    private long totalAssets;
    private long assetsWithAlerts;

    private long totalDetectionRules;
    private long activeDetectionRules;

    private double meanTimeToDetectSeconds; // MTTD
    private double meanTimeToRespondSeconds; // MTTR

    private Map<String, String> subsystemHealth;
    private List<Map<String, Object>> recentIncidents;
    private List<Map<String, Object>> recentActions;
    private List<Map<String, Object>> detectionTacticDistribution;

    public SocOverviewMetricsDto() {}

    public long getTotalIncidents() { return totalIncidents; }
    public void setTotalIncidents(long totalIncidents) { this.totalIncidents = totalIncidents; }

    public long getActiveIncidents() { return activeIncidents; }
    public void setActiveIncidents(long activeIncidents) { this.activeIncidents = activeIncidents; }

    public long getCriticalIncidents() { return criticalIncidents; }
    public void setCriticalIncidents(long criticalIncidents) { this.criticalIncidents = criticalIncidents; }

    public long getHighIncidents() { return highIncidents; }
    public void setHighIncidents(long highIncidents) { this.highIncidents = highIncidents; }

    public long getMediumIncidents() { return mediumIncidents; }
    public void setMediumIncidents(long mediumIncidents) { this.mediumIncidents = mediumIncidents; }

    public long getLowIncidents() { return lowIncidents; }
    public void setLowIncidents(long lowIncidents) { this.lowIncidents = lowIncidents; }

    public long getTotalAssets() { return totalAssets; }
    public void setTotalAssets(long totalAssets) { this.totalAssets = totalAssets; }

    public long getAssetsWithAlerts() { return assetsWithAlerts; }
    public void setAssetsWithAlerts(long assetsWithAlerts) { this.assetsWithAlerts = assetsWithAlerts; }

    public long getTotalDetectionRules() { return totalDetectionRules; }
    public void setTotalDetectionRules(long totalDetectionRules) { this.totalDetectionRules = totalDetectionRules; }

    public long getActiveDetectionRules() { return activeDetectionRules; }
    public void setActiveDetectionRules(long activeDetectionRules) { this.activeDetectionRules = activeDetectionRules; }

    public double getMeanTimeToDetectSeconds() { return meanTimeToDetectSeconds; }
    public void setMeanTimeToDetectSeconds(double meanTimeToDetectSeconds) { this.meanTimeToDetectSeconds = meanTimeToDetectSeconds; }

    public double getMeanTimeToRespondSeconds() { return meanTimeToRespondSeconds; }
    public void setMeanTimeToRespondSeconds(double meanTimeToRespondSeconds) { this.meanTimeToRespondSeconds = meanTimeToRespondSeconds; }

    public Map<String, String> getSubsystemHealth() { return subsystemHealth; }
    public void setSubsystemHealth(Map<String, String> subsystemHealth) { this.subsystemHealth = subsystemHealth; }

    public List<Map<String, Object>> getRecentIncidents() { return recentIncidents; }
    public void setRecentIncidents(List<Map<String, Object>> recentIncidents) { this.recentIncidents = recentIncidents; }

    public List<Map<String, Object>> getRecentActions() { return recentActions; }
    public void setRecentActions(List<Map<String, Object>> recentActions) { this.recentActions = recentActions; }

    public List<Map<String, Object>> getDetectionTacticDistribution() { return detectionTacticDistribution; }
    public void setDetectionTacticDistribution(List<Map<String, Object>> detectionTacticDistribution) { this.detectionTacticDistribution = detectionTacticDistribution; }
}
