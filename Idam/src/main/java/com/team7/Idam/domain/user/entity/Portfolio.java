package com.team7.Idam.domain.user.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(
        name = "portfolio",
        // 학생별 동일 포트폴리오 추가 방지
        uniqueConstraints = {@UniqueConstraint(columnNames = {"user_id", "portfolio"})}
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Portfolio {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "portfolio_id")
    private Long portfolioId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private Student student;

    @Column(length = 255, nullable = false)
    private String portfolio;
}