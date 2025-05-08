package com.team7.Idam.config;

import com.team7.Idam.domain.user.repository.UserRepository;
import com.team7.Idam.jwt.JwtTokenProvider;
import com.team7.Idam.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    // BCrypt >> 비밀번호를 "단방향 해시"로 안전하게 변환해주는 암호화 알고리즘
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // SecurityFilterChain
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // CSRF 토큰 검증 비활성화(-> JWT토큰으로 대체)
                .csrf(csrf -> csrf.disable())
                // 경로별로 접근 허용 여부 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/signup/**",   // 회원가입 허용
                                "/api/login/**",    // 로그인 허용
                                "/api/refresh"      // 토큰 재발급 허용
                        ).permitAll() // 누구나 요청 허용
                        .anyRequest().authenticated()  // 나머지는 인증 필요
                )
                // 기본 필터 앞에 JWT 검증 필터 삽입
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, userRepository), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    // AuthenticationManager Bean 등록
    /*
        유효한 사용자인지(로그인 성공인지 실패인지) 검증.
        Spring Security 내부에 이미 설정된 인증 로직을 빈으로 등록.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
