package com.blueops.correlation;

import com.blueops.incidents.IncidentSeverity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CorrelationRepository extends JpaRepository<CorrelationRecord, Long> {

    Optional<CorrelationRecord> findByCorrelationId(String correlationId);

    List<CorrelationRecord> findByRuleId(String ruleId);

    List<CorrelationRecord> findByPrimaryEntityCanonicalId(String canonicalId);

    @Query("SELECT c FROM CorrelationRecord c WHERE " +
           "(:severity IS NULL OR c.severity = :severity) AND " +
           "(:status IS NULL OR c.status = :status) AND " +
           "(:query IS NULL OR LOWER(c.correlationId) LIKE LOWER(CONCAT('%', :query, '%')) " +
           "OR LOWER(c.ruleName) LIKE LOWER(CONCAT('%', :query, '%')) " +
           "OR LOWER(c.primaryEntityCanonicalId) LIKE LOWER(CONCAT('%', :query, '%')))")
    Page<CorrelationRecord> findFiltered(@Param("severity") IncidentSeverity severity,
                                         @Param("status") CorrelationStatus status,
                                         @Param("query") String query,
                                         Pageable pageable);
}
