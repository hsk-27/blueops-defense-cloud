package com.blueops.incidents;

import java.time.Instant;

public class IncidentTimelineEntryDto {
    private String type; // FINDING, STATUS_CHANGE, NOTE, ACTION
    private Instant timestamp;
    private String title;
    private String description;
    private String actor;
    private String severity;

    public IncidentTimelineEntryDto() {}

    public IncidentTimelineEntryDto(String type, Instant timestamp, String title, String description, String actor, String severity) {
        this.type = type;
        this.timestamp = timestamp;
        this.title = title;
        this.description = description;
        this.actor = actor;
        this.severity = severity;
    }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
}
