package com.team7.Idam.domain.user.dto.profile;

import com.team7.Idam.domain.user.entity.enums.Gender;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class StudentProfileResponseDto {
    private String name;
    private String schoolName;
    private String major;
    private String schoolId;
    private String nickname;
    private Gender gender;
    private String profileImage;
    private String email;
    private String phone;
    private Long categoryId;
    private List<String> tags;
    private List<PortfolioResponseDto> portfolios;
}