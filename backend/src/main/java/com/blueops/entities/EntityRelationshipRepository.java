package com.blueops.entities;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface EntityRelationshipRepository extends JpaRepository<EntityRelationshipRecord, Long> {

    Optional<EntityRelationshipRecord> findBySourceCanonicalIdAndTargetCanonicalIdAndRelationType(
            String sourceCanonicalId, String targetCanonicalId, EntityRelationType relationType);

    List<EntityRelationshipRecord> findBySourceCanonicalIdOrTargetCanonicalId(
            String sourceCanonicalId, String targetCanonicalId);

    Page<EntityRelationshipRecord> findBySourceCanonicalIdOrTargetCanonicalId(
            String sourceCanonicalId, String targetCanonicalId, Pageable pageable);

    @Query("SELECT r FROM EntityRelationshipRecord r WHERE " +
           "(:source IS NULL OR r.sourceCanonicalId = :source) AND " +
           "(:target IS NULL OR r.targetCanonicalId = :target) AND " +
           "(:relType IS NULL OR r.relationType = :relType)")
    Page<EntityRelationshipRecord> findFiltered(@Param("source") String source,
                                                @Param("target") String target,
                                                @Param("relType") EntityRelationType relType,
                                                Pageable pageable);
}
