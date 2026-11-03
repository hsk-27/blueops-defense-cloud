package com.blueops.incidents;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface IncidentRepository extends JpaRepository<Incident, Long> {
    Optional<Incident> findByIncidentNumber(String incidentNumber);
    List<Incident> findByStatus(IncidentStatus status);
    Page<Incident> findByStatus(IncidentStatus status, Pageable pageable);
    long countByStatus(IncidentStatus status);
    long countBySeverity(IncidentSeverity severity);

    @Query("SELECT i FROM Incident i LEFT JOIN FETCH i.primaryAsset WHERE (:status IS NULL OR i.status = :status) AND (:severity IS NULL OR i.severity = :severity)")
    Page<Incident> findFiltered(@Param("status") IncidentStatus status, @Param("severity") IncidentSeverity severity, Pageable pageable);

    @Query("SELECT COUNT(i) FROM Incident i WHERE i.status NOT IN ('RESOLVED', 'FALSE_POSITIVE')")
    long countActiveIncidents();

    @Query("SELECT i FROM Incident i WHERE i.title = :title AND (:assetId IS NULL OR i.primaryAsset.id = :assetId) AND i.status NOT IN ('RESOLVED', 'FALSE_POSITIVE')")
    List<Incident> findActiveByTitleAndAsset(@Param("title") String title, @Param("assetId") Long assetId);

    @Query("SELECT COUNT(DISTINCT i.primaryAsset.id) FROM Incident i WHERE i.primaryAsset IS NOT NULL AND i.status NOT IN ('RESOLVED', 'FALSE_POSITIVE')")
    long countAssetsWithActiveIncidents();

    List<Incident> findTop5ByOrderByCreatedAtDesc();

    List<Incident> findByContainedAtIsNotNullAndCreatedAtIsNotNull();
}
