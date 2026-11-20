package com.blueops.response;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ResponseProposalRepository extends JpaRepository<ResponseProposalRecord, Long> {
    Optional<ResponseProposalRecord> findByProposalUuid(String proposalUuid);
    List<ResponseProposalRecord> findByIncidentIdOrderByProposedAtDesc(Long incidentId);
    Page<ResponseProposalRecord> findByStatusOrderByProposedAtDesc(ProposalStatus status, Pageable pageable);
    List<ResponseProposalRecord> findByStatus(ProposalStatus status);
    Page<ResponseProposalRecord> findAllByOrderByProposedAtDesc(Pageable pageable);
    boolean existsByActionCodeAndTargetIdentifierAndStatusIn(String actionCode, String targetIdentifier, List<ProposalStatus> statuses);
}
