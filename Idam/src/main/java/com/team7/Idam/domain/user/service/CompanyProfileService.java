package com.team7.Idam.domain.user.service;

import com.team7.Idam.domain.user.dto.profile.company.CompanyPreviewResponseDto;
import com.team7.Idam.domain.user.dto.profile.company.CompanyProfileResponseDto;
import com.team7.Idam.domain.user.dto.profile.company.CompanyProfileUpdateRequestDto;
import com.team7.Idam.domain.user.entity.Company;
import com.team7.Idam.domain.user.repository.CompanyRepository;
import com.team7.Idam.global.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CompanyProfileService {

    private final CompanyRepository companyRepository;
    private final FileUploadService fileUploadService;

    // AccessToken 사용자 == 요청된 UserId 일치할 때만 로직 수행.
    public void validateCompanyAccess(Long requestedUserId) {
        Long loginUserId = SecurityUtil.getCurrentUserId(); // JWT 기반 사용자 ID
        if (!loginUserId.equals(requestedUserId)) {
            throw new AccessDeniedException("당사의 정보에만 접근할 수 있습니다.");
        }
    }

    /*
        기업 프로필 전체 조회
     */
    public CompanyProfileResponseDto getCompanyProfile(Long userId) {
        validateCompanyAccess(userId);

        Company company = companyRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("해당 기업을 찾을 수 없습니다."));

        return CompanyProfileResponseDto.builder()
                .companyName(company.getCompanyName())
                .businessRegistrationNumber(company.getBusinessRegistrationNumber())
                .address(company.getAddress())
                .website(company.getWebsite())
                .profileImage(company.getProfileImage())
                .email(company.getUser().getEmail())
                .phone(company.getUser().getPhone())
                .companyDescription(company.getCompanyDescription())
                .build();
    }

    /*
        프로필 이미지 업로드
     */
    public void updateProfileImage(Long userId, MultipartFile file) {
        validateCompanyAccess(userId);

        Company company = companyRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("해당 기업을 찾을 수 없습니다."));

        if (company.getProfileImage() != null) { // 프로필 이미지 이미 존재 시
            fileUploadService.delete(company.getProfileImage()); // S3에서 삭제
        }

        String imageUrl = fileUploadService.upload(file); // S3에 저장

        company.setProfileImage(imageUrl);
        companyRepository.save(company);
    }

    /*
        프로필 이미지 삭제
     */
    public void deleteProfileImage(Long userId) {
        validateCompanyAccess(userId);

        Company company = companyRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("해당 학생을 찾을 수 없습니다."));

        String imageUrl = company.getProfileImage();
        if (imageUrl == null) {
            throw new SecurityException("삭제할 프로필 이미지가 없습니다.");
        }

        fileUploadService.delete(imageUrl); // S3에서 삭제

        company.setProfileImage(null);
        companyRepository.save(company);
    }

    /*
        기업 프로필 정보 수정
     */
    @Transactional
    public void updateCompanyProfile(Long userId, CompanyProfileUpdateRequestDto request) {
        validateCompanyAccess(userId);

        Company company = companyRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("해당 기업을 찾을 수 없습니다."));

        if(request.getCompanyDescription() != null) {
            company.setCompanyDescription(request.getCompanyDescription());
        }
        if(request.getWebsite() != null) {
            company.setWebsite(request.getWebsite());
        }
        if(request.getPhone() != null) {
            company.getUser().setPhone(request.getPhone());
        }
        if(request.getEmail() != null) {
            company.getUser().setEmail(request.getEmail());
        }

        companyRepository.save(company);
    }

    /*
        메인 화면 Preview용 모든 기업 조회 (랜덤 3명)
     */
    public List<CompanyPreviewResponseDto> getAllStudents() {
        List<Company> allStudents = companyRepository.findAll();
        Collections.shuffle(allStudents); // 랜덤 섞기
        return allStudents.stream()
                .limit(3)
                .map(CompanyPreviewResponseDto::from)
                .collect(Collectors.toList());
    }

}
