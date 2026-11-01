package com.blueops.response;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResponseExecutionRepository extends JpaRepository<ResponseExecution, Long> {
    List<ResponseExecution> findByActionId(Long actionId);
    List<ResponseExecution> findTop50ByOrderByExecutedAtDesc();
}
