package com.blueops.advisory;

import com.blueops.incidents.IncidentStatus;
import java.util.Set;

public class AdvisoryAnalysisRequest {
    private IncidentStatus status = IncidentStatus.INVESTIGATING;
    private String severity = "HIGH";
    private Set<String> ruleCodes;
    private Set<String> techniqueIds;
    private String assetTarget;
    private String attackerIp;
    private String username;

    public AdvisoryAnalysisRequest() {}

    public IncidentStatus getStatus() { return status; }
    public void setStatus(IncidentStatus status) { this.status = status; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public Set<String> getRuleCodes() { return ruleCodes; }
    public void setRuleCodes(Set<String> ruleCodes) { this.ruleCodes = ruleCodes; }

    public Set<String> getTechniqueIds() { return techniqueIds; }
    public void setTechniqueIds(Set<String> techniqueIds) { this.techniqueIds = techniqueIds; }

    public String getAssetTarget() { return assetTarget; }
    public void setAssetTarget(String assetTarget) { this.assetTarget = assetTarget; }

    public String getAttackerIp() { return attackerIp; }
    public void setAttackerIp(String attackerIp) { this.attackerIp = attackerIp; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
}
