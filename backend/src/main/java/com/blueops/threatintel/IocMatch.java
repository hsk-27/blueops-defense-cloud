package com.blueops.threatintel;

import com.blueops.assets.Asset;
import com.blueops.incidents.Incident;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "ioc_matches")
public class IocMatch {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ioc_id", nullable = false)
    private IocIndicator ioc;

    @Column(name = "matched_value", nullable = false)
    private String matchedValue;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @Column(name = "event_timestamp", nullable = false)
    private Instant eventTimestamp;

    @Column(name = "opensearch_doc_id", length = 128)
    private String opensearchDocId;

    @Column(name = "matched_field", nullable = false, length = 64)
    private String matchedField;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "incident_id")
    private Incident incident;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public IocMatch() {}

    public IocMatch(IocIndicator ioc, String matchedValue, Asset asset, Instant eventTimestamp, String opensearchDocId, String matchedField) {
        this.ioc = ioc;
        this.matchedValue = matchedValue;
        this.asset = asset;
        this.eventTimestamp = eventTimestamp;
        this.opensearchDocId = opensearchDocId;
        this.matchedField = matchedField;
        this.createdAt = Instant.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public IocIndicator getIoc() { return ioc; }
    public void setIoc(IocIndicator ioc) { this.ioc = ioc; }

    public String getMatchedValue() { return matchedValue; }
    public void setMatchedValue(String matchedValue) { this.matchedValue = matchedValue; }

    public Asset getAsset() { return asset; }
    public void setAsset(Asset asset) { this.asset = asset; }

    public Instant getEventTimestamp() { return eventTimestamp; }
    public void setEventTimestamp(Instant eventTimestamp) { this.eventTimestamp = eventTimestamp; }

    public String getOpensearchDocId() { return opensearchDocId; }
    public void setOpensearchDocId(String opensearchDocId) { this.opensearchDocId = opensearchDocId; }

    public String getMatchedField() { return matchedField; }
    public void setMatchedField(String matchedField) { this.matchedField = matchedField; }

    public Incident getIncident() { return incident; }
    public void setIncident(Incident incident) { this.incident = incident; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
