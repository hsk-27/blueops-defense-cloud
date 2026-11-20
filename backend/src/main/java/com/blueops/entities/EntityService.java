package com.blueops.entities;

import com.blueops.common.dto.PagedResponse;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class EntityService {

    private final EntityRepository entityRepository;
    private final EntityObservationRepository observationRepository;
    private final EntityRelationshipRepository relationshipRepository;
    private final ObjectMapper objectMapper;

    public EntityService(EntityRepository entityRepository,
                         EntityObservationRepository observationRepository,
                         EntityRelationshipRepository relationshipRepository,
                         ObjectMapper objectMapper) {
        this.entityRepository = entityRepository;
        this.observationRepository = observationRepository;
        this.relationshipRepository = relationshipRepository;
        this.objectMapper = objectMapper;
    }

    public PagedResponse<EntityDto> getEntities(EntityType type, EntityStatus status, String query, int page, int size) {
        int boundedSize = Math.min(Math.max(1, size), 100);
        Pageable pageable = PageRequest.of(Math.max(0, page), boundedSize, Sort.by(Sort.Direction.DESC, "lastSeen"));
        Page<EntityRecord> entityPage = entityRepository.findFiltered(type, status, query, pageable);

        List<EntityDto> dtos = entityPage.getContent().stream()
                .map(this::toDto)
                .collect(Collectors.toList());

        return new PagedResponse<>(
                dtos,
                entityPage.getNumber(),
                entityPage.getSize(),
                entityPage.getTotalElements(),
                entityPage.getTotalPages(),
                entityPage.isLast()
        );
    }

    public EntityDto getEntityById(Long id) {
        EntityRecord record = entityRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Entity not found with ID: " + id));
        return toDto(record);
    }

    public EntityDto getEntityByCanonicalId(String canonicalId) {
        EntityRecord record = entityRepository.findByCanonicalId(canonicalId)
                .orElseThrow(() -> new NoSuchElementException("Entity not found with canonical ID: " + canonicalId));
        return toDto(record);
    }

    public PagedResponse<EntityObservationDto> getObservations(Long entityId, int page, int size) {
        int boundedSize = Math.min(Math.max(1, size), 100);
        Pageable pageable = PageRequest.of(Math.max(0, page), boundedSize);
        Page<EntityObservationRecord> obsPage = observationRepository.findByEntityIdOrderByObservedAtDesc(entityId, pageable);

        List<EntityObservationDto> dtos = obsPage.getContent().stream()
                .map(this::toDto)
                .collect(Collectors.toList());

        return new PagedResponse<>(
                dtos,
                obsPage.getNumber(),
                obsPage.getSize(),
                obsPage.getTotalElements(),
                obsPage.getTotalPages(),
                obsPage.isLast()
        );
    }

    public List<EntityRelationshipDto> getRelationships(String canonicalId) {
        if (canonicalId == null || canonicalId.trim().isEmpty()) return Collections.emptyList();
        List<EntityRelationshipRecord> records = relationshipRepository
                .findBySourceCanonicalIdOrTargetCanonicalId(canonicalId, canonicalId);

        return records.stream()
                .map(this::toDto)
                .collect(Collectors.toList());
    }

    public PagedResponse<EntityRelationshipDto> searchRelationships(String source, String target, EntityRelationType relType, int page, int size) {
        int boundedSize = Math.min(Math.max(1, size), 100);
        Pageable pageable = PageRequest.of(Math.max(0, page), boundedSize, Sort.by(Sort.Direction.DESC, "lastObserved"));
        Page<EntityRelationshipRecord> relPage = relationshipRepository.findFiltered(source, target, relType, pageable);

        List<EntityRelationshipDto> dtos = relPage.getContent().stream()
                .map(this::toDto)
                .collect(Collectors.toList());

        return new PagedResponse<>(
                dtos,
                relPage.getNumber(),
                relPage.getSize(),
                relPage.getTotalElements(),
                relPage.getTotalPages(),
                relPage.isLast()
        );
    }

    @Transactional
    public EntityDto updateEntityStatus(Long id, EntityStatus status) {
        EntityRecord record = entityRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Entity not found with ID: " + id));
        record.setStatus(status);
        record.setUpdatedAt(java.time.Instant.now());
        return toDto(entityRepository.save(record));
    }

    // --- Entity Context Aggregation for Investigation Workspaces ---

    public Map<String, Object> getEntityContext(String canonicalId) {
        Map<String, Object> context = new HashMap<>();
        Optional<EntityRecord> entityOpt = entityRepository.findByCanonicalId(canonicalId);
        if (entityOpt.isEmpty()) {
            context.put("found", false);
            return context;
        }

        EntityRecord entity = entityOpt.get();
        context.put("found", true);
        context.put("entity", toDto(entity));

        // Top 20 observations
        List<EntityObservationRecord> topObs = observationRepository.findTop50ByCanonicalIdOrderByObservedAtDesc(canonicalId);
        context.put("recentObservations", topObs.stream().limit(20).map(this::toDto).collect(Collectors.toList()));
        context.put("totalObservationCount", entity.getObservationCount());

        // Relationships
        List<EntityRelationshipRecord> rels = relationshipRepository.findBySourceCanonicalIdOrTargetCanonicalId(canonicalId, canonicalId);
        context.put("relationships", rels.stream().map(this::toDto).collect(Collectors.toList()));

        return context;
    }

    // --- Mappers ---

    public EntityDto toDto(EntityRecord record) {
        if (record == null) return null;
        Map<String, Object> attrs = parseJson(record.getAttributesJson());
        return new EntityDto(
                record.getId(),
                record.getCanonicalId(),
                record.getEntityType(),
                record.getDisplayName(),
                attrs,
                record.getRiskScore(),
                record.getStatus(),
                record.getObservationCount(),
                record.getFirstSeen(),
                record.getLastSeen(),
                record.getCreatedAt()
        );
    }

    public EntityObservationDto toDto(EntityObservationRecord obs) {
        if (obs == null) return null;
        Map<String, Object> attrs = parseJson(obs.getObservedAttributesJson());
        return new EntityObservationDto(
                obs.getId(),
                obs.getEntityId(),
                obs.getCanonicalId(),
                obs.getSourceType(),
                obs.getSourceId(),
                obs.getHostContext(),
                obs.getRawEvidenceRef(),
                attrs,
                obs.getConfidenceScore(),
                obs.getObservedAt()
        );
    }

    public EntityRelationshipDto toDto(EntityRelationshipRecord rel) {
        if (rel == null) return null;
        return new EntityRelationshipDto(
                rel.getId(),
                rel.getSourceCanonicalId(),
                rel.getTargetCanonicalId(),
                rel.getRelationType(),
                rel.getConfidenceScore(),
                rel.getObservationCount(),
                rel.getEvidenceDescription(),
                rel.getProvenanceSource(),
                rel.getFirstObserved(),
                rel.getLastObserved()
        );
    }

    private Map<String, Object> parseJson(String json) {
        if (json == null || json.trim().isEmpty()) return new HashMap<>();
        try {
            return objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            return new HashMap<>();
        }
    }
}
