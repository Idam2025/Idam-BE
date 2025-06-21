package com.team7.Idam.domain.user.service;

import com.team7.Idam.domain.user.dto.login.LoginResultDto;
import com.team7.Idam.domain.user.dto.signup.StudentSignupRequestDto;
import com.team7.Idam.domain.user.dto.signup.CompanySignupRequestDto;
import com.team7.Idam.domain.user.dto.login.LoginRequestDto;
import com.team7.Idam.domain.user.entity.*;
import com.team7.Idam.domain.user.entity.enums.UserType;
import com.team7.Idam.domain.user.entity.enums.UserStatus;
import com.team7.Idam.domain.user.repository.TagCategoryRepository;
import com.team7.Idam.domain.user.repository.UserRepository;
import com.team7.Idam.domain.user.repository.StudentRepository;
import com.team7.Idam.domain.user.repository.CompanyRepository;
import com.team7.Idam.jwt.JwtTokenProvider;
import com.team7.Idam.global.util.RefreshTokenStore;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final StudentRepository studentRepository;
    private final CompanyRepository companyRepository;
    private final TagCategoryRepository tagCategoryRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenStore refreshTokenStore;

    // 학생 회원가입
    public void signupStudent(StudentSignupRequestDto request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("이미 등록된 이메일입니다.");
        }

        if (userRepository.existsByPhone(request.getPhone())) {
            throw new IllegalArgumentException("이미 등록된 전화번호입니다.");
        }

        if (studentRepository.existsByNickname(request.getNickname())) {
            throw new IllegalArgumentException("이미 사용 중인 별명입니다.");
        }

        if (studentRepository.existsBySchoolId(request.getSchoolId())) {
            throw new IllegalArgumentException("이미 등록된 학번입니다.");
        }

        // 💡 카테고리 이름으로 TagCategory 조회
        TagCategory category = tagCategoryRepository.findByCategoryName(request.getCategoryName())
                .orElseThrow(() -> new IllegalArgumentException("해당하는 분야가 존재하지 않습니다."));

        // User 생성
        User user = User.builder()
                .email(request.getEmail())
                .userType(UserType.STUDENT)
                .userStatus(UserStatus.ACTIVE)
                .phone(request.getPhone())
                .build();
        userRepository.save(user);

        // Student 생성
        Student student = Student.builder()
                .user(user)
                .name(request.getName())
                .nickname(request.getNickname())
                .schoolName(request.getSchoolName())
                .major(request.getMajor())
                .schoolId(request.getSchoolId())
                .password(passwordEncoder.encode(request.getPassword()))
                .gender(request.getGender())
                .profileImage(request.getProfileImage())
                .category(category)
                .build();
        studentRepository.save(student);
    }

    // 기업 회원가입
    public void signupCompany(CompanySignupRequestDto request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("이미 등록된 이메일입니다.");
        }

        if (userRepository.existsByPhone(request.getPhone())) {
            throw new IllegalArgumentException("이미 등록된 전화번호입니다.");
        }

        if (companyRepository.existsByBusinessRegistrationNumber(request.getBusinessRegistrationNumber())) {
            throw new IllegalArgumentException("이미 등록된 사업자 등록번호입니다.");
        }

        // User 생성
        User user = User.builder()
                .email(request.getEmail())
                .userType(UserType.COMPANY)
                .userStatus(UserStatus.ACTIVE)
                .phone(request.getPhone())
                .build();
        userRepository.save(user);

        // Company 생성
        Company company = Company.builder()
                .user(user)
                .password(passwordEncoder.encode(request.getPassword()))
                .businessRegistrationNumber(request.getBusinessRegistrationNumber())
                .companyName(request.getCompanyName())
                .address(request.getAddress())
                .website(request.getWebsite())
                .profileImage(request.getProfileImage())
                .build();
        companyRepository.save(company);
    }

    // 로그인
    public LoginResultDto login(LoginRequestDto request) {
        System.out.println("🔥 요청 이메일: " + request.getEmail());
        System.out.println("🔥 받은 디바이스 ID: " + request.getDeviceId());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 이메일입니다."));

        System.out.println("🔥 유저 ID: " + user.getId());
        System.out.println("🔥 유저 타입: " + user.getUserType());

        String raw = request.getPassword();
        String encoded;

        if (user.getUserType() == UserType.STUDENT) {
            Student student = studentRepository.findById(user.getId())
                    .orElseThrow(() -> new IllegalArgumentException("학생 정보가 존재하지 않습니다."));
            encoded = student.getPassword();

            System.out.println("🔥 학생 비밀번호 해시: " + encoded);
        } else if (user.getUserType() == UserType.COMPANY) {
            Company company = companyRepository.findById(user.getId())
                    .orElseThrow(() -> new IllegalArgumentException("기업 정보가 존재하지 않습니다."));
            encoded = company.getPassword();

            System.out.println("🔥 기업 비밀번호 해시: " + encoded);
        } else {
            throw new IllegalArgumentException("지원하지 않는 사용자 타입입니다.");
        }

        if (!passwordEncoder.matches(raw, encoded)) {
            System.out.println("❌ 비밀번호가 일치하지 않음");
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        System.out.println("✅ 비밀번호 일치");

        List<String> roles = List.of("USER");  // 또는 필요 시 조건 처리
        // List<String> roles = List.of("ADMIN");  // ADMIN -> 이건 따로 어드민 만들때 사용(학생, 기업 외 어드민 로그인 장치 마련)
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getUserType().name(), roles);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        System.out.println("✅ accessToken 생성 완료");
        System.out.println("✅ refreshToken 생성 완료");

        refreshTokenStore.save(user.getId(), request.getDeviceId(), refreshToken);
        System.out.println("✅ refreshToken 저장 완료");

        System.out.println("🔥 최종 반환할 userId: " + user.getId());

        return new LoginResultDto(accessToken, refreshToken, user.getUserType().name(), user.getId());
    }

    // Refresh Token으로 Access Token 재발급
    public LoginResultDto reissueToken(Long userId, String deviceId, String refreshToken) {
        if (refreshToken == null) {
            throw new IllegalArgumentException("Refresh Token이 존재하지 않습니다.");
        }

        String storedRefreshToken = refreshTokenStore.get(userId, deviceId);

        if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
            throw new IllegalArgumentException("Refresh Token이 유효하지 않습니다.");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 유저입니다."));

        List<String> roles = user.getUserType() == UserType.STUDENT
                ? List.of("USER")
                : List.of("ADMIN");
        String newAccessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getUserType().name(), roles);

        String newRefreshToken = jwtTokenProvider.generateRefreshToken(user.getId());
        refreshTokenStore.save(user.getId(), deviceId, newRefreshToken);

        return new LoginResultDto(newAccessToken, newRefreshToken, user.getUserType().name(), user.getId());
    }
}
