package com.blueops.threatintel;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface IocMatchRepository extends JpaRepository<IocMatch, Long> {
    List<IocMatch> findByIocId(Long iocId);
    List<IocMatch> findTop50ByOrderByEventTimestampDesc();
}
