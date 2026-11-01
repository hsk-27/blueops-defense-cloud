package com.blueops.threatintel;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "ioc_indicators", uniqueConstraints = {
    @UniqueConstraint(name = "uk_indicator_val_type", columnNames = {"indicator_value", "indicator_type"})
})
public class IocIndicator {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "indicator_value", nullable = false)
    private String indicatorValue;

    @Enumerated(EnumType.STRING)
    @Column(name = "indicator_type", nullable = false, length = 32)
    private IocType indicatorType;

    @Column(nullable = false, length = 64)
    private String source;

    @Column(nullable = false)
    private int confidence; // 0 to 100

    @Column(nullable = false, length = 32)
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(nullable = false, length = 32)
    private String status = "ACTIVE"; // ACTIVE, REVOKED, EXPIRED

    @Column(name = "first_seen_at", nullable = false)
    private Instant firstSeenAt = Instant.now();

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt = Instant.now();

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(length = 255)
    private String tags;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public IocIndicator() {}

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
