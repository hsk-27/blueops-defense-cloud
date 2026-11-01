package com.blueops.assets;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AssetRepository extends JpaRepository<Asset, Long> {
    Optional<Asset> findByPersistentId(String persistentId);
    Optional<Asset> findByHostname(String hostname);
    Optional<Asset> findByIpAddress(String ipAddress);
    boolean existsByPersistentId(String persistentId);
}
