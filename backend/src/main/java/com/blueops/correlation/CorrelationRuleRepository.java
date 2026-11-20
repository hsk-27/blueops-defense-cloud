package com.blueops.correlation;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CorrelationRuleRepository extends JpaRepository<CorrelationRuleRecord, Long> {

    Optional<CorrelationRuleRecord> findByRuleId(String ruleId);

    List<CorrelationRuleRecord> findByEnabledTrue();
}
