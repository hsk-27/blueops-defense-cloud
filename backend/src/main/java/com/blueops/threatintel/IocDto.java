package com.blueops.threatintel;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public class IocDto {
    private Long id;

    @NotBlank(message = "Indicator value is required")
    private String indicatorValue;

    @NotNull(message = "Indicator type is required")
    private IocType indicatorType;

    @NotBlank(message = "Source is required")
    private String source;

    @Min(0) @Max(100)
    private int confidence = 80;

    @NotBlank(message = "Severity is required")
    private String severity;

    private String description;
    private String status;
    private Instant firstSeenAt;
    private Instant lastSeenAt;
    private Instant expiresAt;
    private String tags;
    private Instant createdAt;

    public IocDto() {}

    public IocDto(IocIndicator ioc) {
        this.id = ioc.getId();
        this.indicatorValue = ioc.getIndicatorValue();
        this.indicatorType = ioc.getIndicatorType();
        this.source = ioc.getSource();
        this.confidence = ioc.getConfidence();
        this.severity = ioc.getSeverity();
        this.description = ioc.getDescription();
        this.status = ioc.getStatus();
        this.firstSeenAt = ioc.getFirstSeenAt();
        this.lastSeenAt = ioc.getLastSeenAt();
        this.expiresAt = ioc.getExpiresAt();
        this.tags = ioc.getTags();
        this.createdAt = ioc.getCreatedAt();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getIndicatorValue() { return indicatorValue; }
    public void setIndicatorValue(String indicatorValue) { this.indicatorValue = indicatorValue; }

    public IocType getIndicatorType() { return indicatorType; }
    public void setIndicatorType(IocType indicatorType) { this.indicatorType = indicatorType; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public int getConfidence() { return confidence; }
    public void setConfidence(int confidence) { this.confidence = confidence; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Instant getFirstSeenAt() { return firstSeenAt; }
    public void setFirstSeenAt(Instant firstSeenAt) { this.firstSeenAt = firstSeenAt; }

    public Instant getLastSeenAt() { return lastSeenAt; }
    public void setLastSeenAt(Instant lastSeenAt) { this.lastSeenAt = lastSeenAt; }

    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }

    public String getTags() { return tags; }
    public void setTags(String tags) { this.tags = tags; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
