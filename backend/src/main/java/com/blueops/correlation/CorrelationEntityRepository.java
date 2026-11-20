package com.blueops.correlation;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CorrelationEntityRepository extends JpaRepository<CorrelationEntityRecord, Long> {

    List<CorrelationEntityRecord> findByCorrelationId(Long correlationId);

    List<CorrelationEntityRecord> findByEntityCanonicalId(String entityCanonicalId);

    boolean existsByCorrelationIdAndEntityCanonicalId(Long correlationId, String entityCanonicalId);
}
