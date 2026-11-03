package com.blueops.advisory;

import java.util.List;

public class IncidentRecommendationDto {
    private String id;
    private String title;
    private AdvisoryPhase phase;
    private AdvisoryPriority priority;
    private AuthoritativeSource authoritativeSource;
    private String citation;
    private String rationale;
    private List<String> actionableSteps;
    private String suggestedPlaybookCode;
    private String suggestedPlaybookName;
    private String suggestedTarget;
    private List<String> applicableTechniques;

    public IncidentRecommendationDto() {}

    public IncidentRecommendationDto(
            String id,
            String title,
            AdvisoryPhase phase,
            AdvisoryPriority priority,
            AuthoritativeSource authoritativeSource,
            String citation,
            String rationale,
            List<String> actionableSteps,
            String suggestedPlaybookCode,
            String suggestedPlaybookName,
            String suggestedTarget,
            List<String> applicableTechniques) {
        this.id = id;
        this.title = title;
        this.phase = phase;
        this.priority = priority;
        this.authoritativeSource = authoritativeSource;
        this.citation = citation;
        this.rationale = rationale;
        this.actionableSteps = actionableSteps;
        this.suggestedPlaybookCode = suggestedPlaybookCode;
        this.suggestedPlaybookName = suggestedPlaybookName;
        this.suggestedTarget = suggestedTarget;
        this.applicableTechniques = applicableTechniques;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public AdvisoryPhase getPhase() { return phase; }
    public void setPhase(AdvisoryPhase phase) { this.phase = phase; }

    public AdvisoryPriority getPriority() { return priority; }
    public void setPriority(AdvisoryPriority priority) { this.priority = priority; }

    public AuthoritativeSource getAuthoritativeSource() { return authoritativeSource; }
    public void setAuthoritativeSource(AuthoritativeSource authoritativeSource) { this.authoritativeSource = authoritativeSource; }

    public String getCitation() { return citation; }
    public void setCitation(String citation) { this.citation = citation; }

    public String getRationale() { return rationale; }
    public void setRationale(String rationale) { this.rationale = rationale; }

    public List<String> getActionableSteps() { return actionableSteps; }
    public void setActionableSteps(List<String> actionableSteps) { this.actionableSteps = actionableSteps; }

    public String getSuggestedPlaybookCode() { return suggestedPlaybookCode; }
    public void setSuggestedPlaybookCode(String suggestedPlaybookCode) { this.suggestedPlaybookCode = suggestedPlaybookCode; }

    public String getSuggestedPlaybookName() { return suggestedPlaybookName; }
    public void setSuggestedPlaybookName(String suggestedPlaybookName) { this.suggestedPlaybookName = suggestedPlaybookName; }

    public String getSuggestedTarget() { return suggestedTarget; }
    public void setSuggestedTarget(String suggestedTarget) { this.suggestedTarget = suggestedTarget; }

    public List<String> getApplicableTechniques() { return applicableTechniques; }
    public void setApplicableTechniques(List<String> applicableTechniques) { this.applicableTechniques = applicableTechniques; }
}
