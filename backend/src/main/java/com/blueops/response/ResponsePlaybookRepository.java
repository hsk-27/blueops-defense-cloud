package com.blueops.response;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ResponsePlaybookRepository extends JpaRepository<ResponsePlaybook, Long> {
    Optional<ResponsePlaybook> findByPlaybookCode(String playbookCode);
}
