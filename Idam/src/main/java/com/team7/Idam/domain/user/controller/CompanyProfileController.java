package com.team7.Idam.domain.user.controller;

import com.team7.Idam.domain.user.dto.profile.CompanyProfileResponseDto;
import com.team7.Idam.domain.user.service.CompanyProfileService;
import com.team7.Idam.global.dto.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/company")
@RequiredArgsConstructor
public class CompanyProfileController {

    private final CompanyProfileService companyService;

    // 프로필 전체 조회
    @GetMapping("/{userId}/profile")
    public ResponseEntity<ApiResponse<CompanyProfileResponseDto>> getCompanyProfile(@PathVariable Long userId) {
        CompanyProfileResponseDto profile = companyService.getCompanyProfile(userId);
        return ResponseEntity.ok(ApiResponse.success("프로필 조회 성공", profile));
    }

    // 프로필 이미지 추가/수정
    @PutMapping("/{userId}/profile/image")
    public ResponseEntity<ApiResponse<Void>> updateProfileImage(@PathVariable Long userId, @RequestPart("profileImage") MultipartFile file) {
        companyService.updateProfileImage(userId, file);
        return ResponseEntity.ok(ApiResponse.success("프로필 이미지가 수정되었습니다."));
    }

    // 프로필 이미지 삭제
    @DeleteMapping("/{userId}/profile/image")
    public ResponseEntity<ApiResponse<Void>> deleteProfileImage(@PathVariable Long userId) {
        companyService.deleteProfileImage(userId);
        return ResponseEntity.ok(ApiResponse.success("프로필 이미지가 삭제되었습니다."));
    }
}
