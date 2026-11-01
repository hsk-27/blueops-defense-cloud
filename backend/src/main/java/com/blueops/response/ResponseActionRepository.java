package com.blueops.response;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ResponseActionRepository extends JpaRepository<ResponseAction, Long> {
    Optional<ResponseAction> findByActionUuid(String actionUuid);
    List<ResponseAction> findByIncidentId(Long incidentId);
    List<ResponseAction> findByApprovalStatus(String approvalStatus);
    List<ResponseAction> findTop25ByOrderByCreatedAtDesc();
}
