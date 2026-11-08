package com.blueops.threatintel;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface IocIndicatorRepository extends JpaRepository<IocIndicator, Long> {
    Optional<IocIndicator> findByIndicatorValueAndIndicatorType(String indicatorValue, IocType indicatorType);
    Optional<IocIndicator> findByIndicatorValue(String indicatorValue);
    Optional<IocIndicator> findByIndicatorValueIgnoreCase(String indicatorValue);
    List<IocIndicator> findByStatus(String status);
    List<IocIndicator> findByIndicatorType(IocType indicatorType);
    boolean existsByIndicatorValueAndIndicatorType(String indicatorValue, IocType indicatorType);
}
