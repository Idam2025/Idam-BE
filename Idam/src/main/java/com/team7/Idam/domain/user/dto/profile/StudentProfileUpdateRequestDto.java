package com.team7.Idam.domain.user.dto.profile;

import com.team7.Idam.domain.user.entity.enums.Gender;
import lombok.Data;

@Data
public class StudentProfileUpdateRequestDto {
    private String nickname;
    private Gender gender;
    private String profileImage;
}