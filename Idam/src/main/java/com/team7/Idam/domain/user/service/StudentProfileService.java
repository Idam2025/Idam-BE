package com.team7.Idam.domain.user.service;

import com.team7.Idam.domain.user.dto.profile.PortfolioRequestDto;
import com.team7.Idam.domain.user.dto.profile.StudentProfileResponseDto;
import com.team7.Idam.domain.user.dto.profile.StudentProfileUpdateRequestDto;
import com.team7.Idam.domain.user.entity.Portfolio;
import com.team7.Idam.domain.user.entity.Student;
import com.team7.Idam.domain.user.entity.TagOption;
import com.team7.Idam.domain.user.repository.PortfolioRepository;
import com.team7.Idam.domain.user.repository.StudentRepository;
import com.team7.Idam.domain.user.repository.TagOptionRepository;
import com.team7.Idam.jwt.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class StudentProfileService {

    private final StudentRepository studentRepository;
    private final PortfolioRepository portfolioRepository;
    private final TagOptionRepository tagOptionRepository;

    // 학생 프로필 조회
    public StudentProfileResponseDto getStudentProfile(Long studentId) {
        Student student = studentRepository.findById(studentId)
                .orElseThrow(() -> new IllegalArgumentException("해당 학생을 찾을 수 없습니다."));

        return StudentProfileResponseDto.builder()
                .name(student.getName())
                .schoolName(student.getSchoolName())
                .major(student.getMajor())
                .schoolId(student.getSchoolId())
                .nickname(student.getNickname())
                .gender(student.getGender())
                .profileImage(student.getProfileImage())
                .email(student.getUser().getEmail())
                .phone(student.getUser().getPhone())
                .build();
    }

    // 학생 프로필 수정
    public void updateStudentProfile(Long studentId, StudentProfileUpdateRequestDto request) {
        Student student = studentRepository.findById(studentId)
                .orElseThrow(() -> new IllegalArgumentException("해당 학생을 찾을 수 없습니다."));

        Long currentUserId = getCurrentUserId();  // JWT에서 추출
        if (!student.getUser().getId().equals(currentUserId)) {
            throw new AccessDeniedException("본인만 수정할 수 있습니다.");
        }

        if (request.getNickname() != null) {
            student.setNickname(request.getNickname());
        }
        if (request.getGender() != null) {
            student.setGender(request.getGender());
        }
        if (request.getProfileImage() != null) {
            student.setProfileImage(request.getProfileImage());
        }

        studentRepository.save(student);
    }

    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        return userDetails.getId();
    }

    // 포트폴리오 추가
    public void addPortfolio(Long studentId, PortfolioRequestDto request) {
        Student student = studentRepository.findById(studentId)
                .orElseThrow(() -> new IllegalArgumentException("학생을 찾을 수 없습니다."));

        boolean exists = portfolioRepository.existsByStudentIdAndPortfolio(studentId, request.getPortfolio());
        if (exists) {
            throw new IllegalArgumentException("이미 동일한 포트폴리오가 등록되어 있습니다.");
        }

        Portfolio portfolio = Portfolio.builder()
                .student(student)
                .portfolio(request.getPortfolio())
                .build();

        portfolioRepository.save(portfolio);
    }

    // 포트폴리오 삭제
    public void deletePortfolio(Long studentId, Long portfolioId) {
        Portfolio portfolio = portfolioRepository.findById(portfolioId)
                .orElseThrow(() -> new IllegalArgumentException("포트폴리오를 찾을 수 없습니다."));

        if (!portfolio.getStudent().getId().equals(studentId)) {
            throw new SecurityException("본인만 삭제할 수 있습니다.");
        }

        portfolioRepository.delete(portfolio);
    }

    // 태그 추가
    public void addStudentTag(Long studentId, Long tagId) {
        Student student = studentRepository.findById(studentId)
                .orElseThrow(() -> new IllegalArgumentException("학생을 찾을 수 없습니다."));

        TagOption tag = tagOptionRepository.findById(tagId)
                .orElseThrow(() -> new IllegalArgumentException("태그를 찾을 수 없습니다."));

        if (student.getTags().contains(tag)) {
            throw new IllegalArgumentException("이미 추가된 태그입니다.");
        }

        student.getTags().add(tag);
        studentRepository.save(student);
    }

    // 태그 수정
    public void updateStudentTags(Long studentId, List<Long> tagIds) {
        Student student = studentRepository.findById(studentId)
                .orElseThrow(() -> new IllegalArgumentException("학생을 찾을 수 없습니다."));

        List<TagOption> newTags = tagOptionRepository.findAllById(tagIds);

        student.setTags(newTags);
        studentRepository.save(student);
    }

    // 태그 삭제
    public void removeStudentTag(Long studentId, Long tagId) {
        Student student = studentRepository.findById(studentId)
                .orElseThrow(() -> new IllegalArgumentException("학생을 찾을 수 없습니다."));

        TagOption tag = tagOptionRepository.findById(tagId)
                .orElseThrow(() -> new IllegalArgumentException("태그를 찾을 수 없습니다."));

        if (!student.getTags().contains(tag)) {
            throw new IllegalArgumentException("학생에게 해당 태그가 존재하지 않습니다.");
        }

        student.getTags().remove(tag);
        studentRepository.save(student);
    }
}
