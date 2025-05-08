package com.team7.Idam.jwt;

import com.team7.Idam.domain.user.entity.User;
import com.team7.Idam.domain.user.entity.enums.UserType;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
public class CustomUserDetails implements UserDetails {

    private final Long id;
    private final String email;
    private final UserType userType;

    public CustomUserDetails(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.userType = user.getUserType();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> userType.name()); // ROLE_STUDENT, ROLE_COMPANY 같은 문자열
    }

    @Override
    public String getUsername() {
        return email;  // 로그인 시 아이디로 사용할 값
    }

    @Override
    public String getPassword() {
        return null; // JWT 기반 인증이므로 null 반환
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}
