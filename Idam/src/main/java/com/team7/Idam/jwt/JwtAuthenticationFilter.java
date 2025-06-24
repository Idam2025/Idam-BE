package com.team7.Idam.jwt;

import com.team7.Idam.domain.user.entity.User;
import com.team7.Idam.domain.user.repository.UserRepository;
import com.team7.Idam.global.util.SlackNotifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.Claims;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final SlackNotifier slackNotifier;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String uri = request.getRequestURI();
        String method = request.getMethod();

        // ✅ 슬랙 알림: 민감 경로 접근 시
        if (uri.startsWith("/admin") || uri.startsWith("/manager")) {
            slackNotifier.sendMessage("🚨 /admin 또는 /manager 접근 감지\nURI: " + uri +
                    "\nMethod: " + method + "\nIP: " + request.getRemoteAddr());
        }

        if ("OPTIONS".equalsIgnoreCase(method) ||
                uri.startsWith("/ws/") ||
                uri.contains("/sockjs") ||
                uri.contains("/info") || // 이거는 "/ws/chat/info"를 포함하지 않을 수 있음
                uri.equals("/ws/chat/info") || // 🔥 정확히 이 줄 추가
                uri.equals("/info")) {
            filterChain.doFilter(request, response);
            return;
        }

        // ✅ 3. 인증 필요 없는 API 경로 제외
        if (uri.startsWith("/api/refresh") || uri.startsWith("/api/login") || uri.startsWith("/api/signup")) {
            filterChain.doFilter(request, response);
            return;
        }

        // ✅ 4. JWT 토큰 파싱
        String token = resolveToken(request);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            Long userId = jwtTokenProvider.getUserIdFromToken(token);
            Claims claims = jwtTokenProvider.getClaims(token);

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

            List<String> roles = claims.get("roles", List.class);

            List<SimpleGrantedAuthority> authorities = roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(Collectors.toList());

            CustomUserDetails customUserDetails = new CustomUserDetails(user);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(customUserDetails, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        // ✅ 1. 헤더에서 추출
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        // ✅ 2. 쿼리 파라미터에서 추출 (WebSocket fallback)
        String tokenParam = request.getParameter("token");
        if (tokenParam != null && !tokenParam.isBlank()) {
            return tokenParam;
        }

        return null;
    }
}
