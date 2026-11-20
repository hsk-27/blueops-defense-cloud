package com.blueops.response;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ResponseActionCatalogRepository extends JpaRepository<ResponseActionDefinition, Long> {
    Optional<ResponseActionDefinition> findByActionCode(String actionCode);
    List<ResponseActionDefinition> findByIsEnabledTrue();
    List<ResponseActionDefinition> findByCategoryAndIsEnabledTrue(String category);
}
