package com.blueops.entities;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface EntityObservationRepository extends JpaRepository<EntityObservationRecord, Long> {

    Page<EntityObservationRecord> findByEntityIdOrderByObservedAtDesc(Long entityId, Pageable pageable);

    Page<EntityObservationRecord> findByCanonicalIdOrderByObservedAtDesc(String canonicalId, Pageable pageable);

    List<EntityObservationRecord> findTop50ByCanonicalIdOrderByObservedAtDesc(String canonicalId);

    long countByEntityId(Long entityId);

    long countByCanonicalId(String canonicalId);
}
