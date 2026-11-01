package com.blueops.detections;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DetectionRuleRepository extends JpaRepository<DetectionRule, Long> {
    Optional<DetectionRule> findByRuleCode(String ruleCode);
    List<DetectionRule> findByStatus(String status);
    List<DetectionRule> findByLogSource(String logSource);
    long countByStatus(String status);
}
