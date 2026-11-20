package com.blueops.entities;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EntityRepository extends JpaRepository<EntityRecord, Long> {

    Optional<EntityRecord> findByCanonicalId(String canonicalId);

    boolean existsByCanonicalId(String canonicalId);

    Page<EntityRecord> findByEntityType(EntityType entityType, Pageable pageable);

    @Query("SELECT e FROM EntityRecord e WHERE " +
           "(:type IS NULL OR e.entityType = :type) AND " +
           "(:status IS NULL OR e.status = :status) AND " +
           "(:query IS NULL OR LOWER(e.displayName) LIKE LOWER(CONCAT('%', :query, '%')) " +
           "OR LOWER(e.canonicalId) LIKE LOWER(CONCAT('%', :query, '%')))")
    Page<EntityRecord> findFiltered(@Param("type") EntityType type,
                                    @Param("status") EntityStatus status,
                                    @Param("query") String query,
                                    Pageable pageable);
}
