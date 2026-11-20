package com.blueops.entities;

import com.blueops.common.dto.PagedResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class EntityController {

    private final EntityService entityService;

    public EntityController(EntityService entityService) {
        this.entityService = entityService;
    }

    @GetMapping("/entities")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<PagedResponse<EntityDto>> getEntities(
            @RequestParam(required = false) EntityType type,
            @RequestParam(required = false) EntityStatus status,
            @RequestParam(required = false) String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(entityService.getEntities(type, status, query, page, size));
    }

    @GetMapping("/entities/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<EntityDto> getEntityById(@PathVariable Long id) {
        return ResponseEntity.ok(entityService.getEntityById(id));
    }

    @GetMapping("/entities/by-canonical/{canonicalId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<EntityDto> getEntityByCanonicalId(@PathVariable String canonicalId) {
        return ResponseEntity.ok(entityService.getEntityByCanonicalId(canonicalId));
    }

    @GetMapping("/entities/{id}/observations")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<PagedResponse<EntityObservationDto>> getObservations(
            @PathVariable Long id,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(entityService.getObservations(id, page, size));
    }

    @GetMapping("/entities/{id}/relationships")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<List<EntityRelationshipDto>> getEntityRelationships(@PathVariable Long id) {
        EntityDto entity = entityService.getEntityById(id);
        return ResponseEntity.ok(entityService.getRelationships(entity.getCanonicalId()));
    }

    @GetMapping("/entities/{id}/context")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<Map<String, Object>> getEntityContext(@PathVariable Long id) {
        EntityDto entity = entityService.getEntityById(id);
        return ResponseEntity.ok(entityService.getEntityContext(entity.getCanonicalId()));
    }

    @PatchMapping("/entities/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<EntityDto> updateEntityStatus(
            @PathVariable Long id,
            @RequestParam EntityStatus status) {
        return ResponseEntity.ok(entityService.updateEntityStatus(id, status));
    }

    @GetMapping("/relationships")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST', 'VIEWER')")
    public ResponseEntity<PagedResponse<EntityRelationshipDto>> searchRelationships(
            @RequestParam(required = false) String source,
            @RequestParam(required = false) String target,
            @RequestParam(required = false) EntityRelationType relType,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(entityService.searchRelationships(source, target, relType, page, size));
    }
}
