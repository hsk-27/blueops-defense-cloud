package com.blueops.response;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ResponseTargetRepository extends JpaRepository<ResponseTargetRecord, Long> {
    Optional<ResponseTargetRecord> findByTargetId(String targetId);
    Optional<ResponseTargetRecord> findByIdentifierIgnoreCase(String identifier);
    List<ResponseTargetRecord> findByTargetType(String targetType);
    List<ResponseTargetRecord> findByTrustStatus(String trustStatus);
}
