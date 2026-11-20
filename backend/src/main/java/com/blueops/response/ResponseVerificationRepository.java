package com.blueops.response;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ResponseVerificationRepository extends JpaRepository<ResponseVerificationRecord, Long> {
    Optional<ResponseVerificationRecord> findByVerificationUuid(String verificationUuid);
    List<ResponseVerificationRecord> findByProposalIdOrderByVerifiedAtDesc(Long proposalId);
    Optional<ResponseVerificationRecord> findTopByProposalIdOrderByVerifiedAtDesc(Long proposalId);
}
