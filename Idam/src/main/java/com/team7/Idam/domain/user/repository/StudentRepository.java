package com.team7.Idam.domain.user.repository;

import com.team7.Idam.domain.user.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface StudentRepository extends JpaRepository<Student, Long> {
    Optional<Student> findByUserId(Long userId);
}