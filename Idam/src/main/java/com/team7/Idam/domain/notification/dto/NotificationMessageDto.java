package com.team7.Idam.domain.notification.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NotificationMessageDto {
    private Long notificationId;
    private Long chatRoomId;
    private String projectTitle;
    private String otherUserName;
    private String profileImageUrl;
    private String message;
    private LocalDateTime createdAt;
    private String type;
}
