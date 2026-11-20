package com.blueops.entities;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

@Service
public class EntityResolutionService {

    private static final Logger log = LoggerFactory.getLogger(EntityResolutionService.class);
    private final EntityRepository entityRepository;
    private final EntityObservationRepository observationRepository;
    private final EntityRelationshipRepository relationshipRepository;
    private final ObjectMapper objectMapper;

    public EntityResolutionService(EntityRepository entityRepository,
                                   EntityObservationRepository observationRepository,
                                   EntityRelationshipRepository relationshipRepository,
                                   ObjectMapper objectMapper) {
        this.entityRepository = entityRepository;
        this.observationRepository = observationRepository;
        this.relationshipRepository = relationshipRepository;
        this.objectMapper = objectMapper;
    }

    // --- Canonical Identifier Normalization ---

    public String buildHostCanonicalId(String hostname) {
        if (hostname == null || hostname.trim().isEmpty()) return null;
        String clean = hostname.trim().toLowerCase();
        // If hostname is FQDN (e.g. host.corp.net), extract primary hostname for uniform enterprise mapping
        if (clean.contains(".")) {
            clean = clean.split("\\.")[0];
        }
        return "host:" + clean;
    }

    public String buildUserCanonicalId(String username) {
        if (username == null || username.trim().isEmpty()) return null;
        String clean = username.trim().toLowerCase().replace('/', '\\');
        return "user:" + clean;
    }

    public String buildIpCanonicalId(String ip) {
        if (ip == null || ip.trim().isEmpty()) return null;
        String clean = ip.trim().toLowerCase();
        // Basic normalization: strip brackets if IPv6
        if (clean.startsWith("[") && clean.endsWith("]")) {
            clean = clean.substring(1, clean.length() - 1);
        }
        return "ip:" + clean;
    }

    public String buildDomainCanonicalId(String domain) {
        if (domain == null || domain.trim().isEmpty()) return null;
        String clean = domain.trim().toLowerCase();
        if (clean.endsWith(".")) {
            clean = clean.substring(0, clean.length() - 1);
        }
        return "domain:" + clean;
    }

    public String buildProcessCanonicalId(String hostname, String processName, Long pid) {
        if (processName == null || processName.trim().isEmpty()) return null;
        String host = hostname != null ? hostname.trim().toLowerCase() : "unknown-host";
        if (host.contains(".")) host = host.split("\\.")[0];
        String proc = processName.trim().toLowerCase();
        if (proc.contains("\\")) proc = proc.substring(proc.lastIndexOf('\\') + 1);
        if (proc.contains("/")) proc = proc.substring(proc.lastIndexOf('/') + 1);

        if (pid != null && pid > 0) {
            return "proc:" + host + ":" + proc + ":" + pid;
        }
        return "proc:" + host + ":" + proc;
    }

    public String buildFileCanonicalId(String hostname, String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) return null;
        String host = hostname != null ? hostname.trim().toLowerCase() : "unknown-host";
        if (host.contains(".")) host = host.split("\\.")[0];
        String path = filePath.trim().replace('\\', '/').toLowerCase();
        return "file:" + host + ":" + path;
    }

    public String buildHashCanonicalId(String algorithm, String hash) {
        if (hash == null || hash.trim().isEmpty()) return null;
        String algo = (algorithm != null && !algorithm.trim().isEmpty()) ? algorithm.trim().toLowerCase() : "sha256";
        String cleanHash = hash.trim().toLowerCase();
        return "hash:" + algo + ":" + cleanHash;
    }

    // --- Entity Resolution & Upsert ---

    @Transactional
    public EntityRecord resolveOrCreateEntity(EntityType type, String canonicalId, String displayName,
                                             Map<String, Object> attributes, double riskIncrement) {
        if (canonicalId == null || canonicalId.trim().isEmpty()) {
            throw new IllegalArgumentException("canonicalId cannot be null or empty");
        }

        Optional<EntityRecord> existingOpt = entityRepository.findByCanonicalId(canonicalId);
        EntityRecord entity;

        if (existingOpt.isPresent()) {
            entity = existingOpt.get();
            entity.setLastSeen(Instant.now());
            entity.setObservationCount(entity.getObservationCount() + 1);

            // Bounded incremental risk scoring (cap at 100.0)
            if (riskIncrement > 0) {
                entity.setRiskScore(Math.min(100.0, entity.getRiskScore() + riskIncrement));
                if (entity.getRiskScore() >= 80.0 && entity.getStatus() != EntityStatus.COMPROMISED) {
                    entity.setStatus(EntityStatus.COMPROMISED);
                } else if (entity.getRiskScore() >= 40.0 && entity.getStatus() == EntityStatus.ACTIVE) {
                    entity.setStatus(EntityStatus.SUSPICIOUS);
                }
            }

            // Safe attribute merging (prevent attribute poisoning)
            if (attributes != null && !attributes.isEmpty()) {
                Map<String, Object> currentAttrs = parseAttributes(entity.getAttributesJson());
                for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                    if (entry.getValue() != null && !currentAttrs.containsKey(entry.getKey())) {
                        currentAttrs.put(entry.getKey(), entry.getValue());
                    }
                }
                entity.setAttributesJson(serializeAttributes(currentAttrs));
            }
            entity.setUpdatedAt(Instant.now());
        } else {
            entity = new EntityRecord(canonicalId, type, displayName != null ? displayName : canonicalId);
            entity.setRiskScore(Math.min(100.0, Math.max(0.0, riskIncrement)));
            if (entity.getRiskScore() >= 80.0) {
                entity.setStatus(EntityStatus.COMPROMISED);
            } else if (entity.getRiskScore() >= 40.0) {
                entity.setStatus(EntityStatus.SUSPICIOUS);
            } else {
                entity.setStatus(EntityStatus.ACTIVE);
            }
            if (attributes != null && !attributes.isEmpty()) {
                entity.setAttributesJson(serializeAttributes(attributes));
            }
            entity = entityRepository.save(entity);
            log.info("Resolved new canonical entity: [{}] {}", entity.getEntityType(), entity.getCanonicalId());
        }

        return entityRepository.save(entity);
    }

    @Transactional
    public EntityObservationRecord recordObservation(EntityRecord entity, String sourceType, String sourceId,
                                                     String hostContext, String rawEvidenceRef,
                                                     Map<String, Object> observedAttributes,
                                                     double confidence, Instant observedAt) {
        if (entity == null || entity.getId() == null) return null;

        String attrsJson = observedAttributes != null ? serializeAttributes(observedAttributes) : null;
        EntityObservationRecord obs = new EntityObservationRecord(
                entity.getId(),
                entity.getCanonicalId(),
                sourceType != null ? sourceType : "TELEMETRY",
                sourceId,
                hostContext,
                rawEvidenceRef,
                attrsJson,
                confidence,
                observedAt != null ? observedAt : Instant.now()
        );
        return observationRepository.save(obs);
    }

    @Transactional
    public EntityRelationshipRecord recordRelationship(String sourceCanonicalId, String targetCanonicalId,
                                                       EntityRelationType relationType, double confidenceScore,
                                                       String evidenceDescription, String provenanceSource) {
        if (sourceCanonicalId == null || targetCanonicalId == null || relationType == null) return null;
        if (sourceCanonicalId.equalsIgnoreCase(targetCanonicalId)) return null; // Avoid self-loops

        Optional<EntityRelationshipRecord> existingOpt = relationshipRepository
                .findBySourceCanonicalIdAndTargetCanonicalIdAndRelationType(sourceCanonicalId, targetCanonicalId, relationType);

        EntityRelationshipRecord rel;
        if (existingOpt.isPresent()) {
            rel = existingOpt.get();
            rel.setLastObserved(Instant.now());
            rel.setObservationCount(rel.getObservationCount() + 1);
            rel.setConfidenceScore(Math.max(rel.getConfidenceScore(), confidenceScore));
            if (evidenceDescription != null) rel.setEvidenceDescription(evidenceDescription);
            rel.setUpdatedAt(Instant.now());
        } else {
            rel = new EntityRelationshipRecord(
                    sourceCanonicalId,
                    targetCanonicalId,
                    relationType,
                    confidenceScore,
                    evidenceDescription,
                    provenanceSource
            );
        }
        return relationshipRepository.save(rel);
    }

    // --- JSON Serialization Helpers ---

    private Map<String, Object> parseAttributes(String json) {
        if (json == null || json.trim().isEmpty()) return new HashMap<>();
        try {
            return objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            log.debug("Failed to deserialize entity attributes JSON: {}", e.getMessage());
            return new HashMap<>();
        }
    }

    private String serializeAttributes(Map<String, Object> map) {
        if (map == null || map.isEmpty()) return null;
        try {
            return objectMapper.writeValueAsString(map);
        } catch (Exception e) {
            log.warn("Failed to serialize entity attributes to JSON: {}", e.getMessage());
            return null;
        }
    }
}
