package com.blueops.correlation;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CorrelationFindingRepository extends JpaRepository<CorrelationFindingRecord, Long> {

    List<CorrelationFindingRecord> findByCorrelationId(Long correlationId);

    List<CorrelationFindingRecord> findByFindingId(String findingId);

    boolean existsByCorrelationIdAndFindingId(Long correlationId, String findingId);
}
