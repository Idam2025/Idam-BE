package com.team7.Idam.domain.user.repository;

import com.team7.Idam.domain.user.entity.Portfolio;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PortfolioRepository extends JpaRepository<Portfolio, Long> {
    boolean existsByStudentIdAndPortfolio(Long studentId, String portfolio);
}
