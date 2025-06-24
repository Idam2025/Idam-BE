package com.team7.Idam.domain.chat.service;

import com.team7.Idam.domain.chat.dto.ChatMessageResponseDto;
import com.team7.Idam.domain.chat.entity.ChatMessage;
import com.team7.Idam.domain.chat.entity.ChatRoom;
import com.team7.Idam.domain.chat.repository.ChatMessageRepository;
import com.team7.Idam.domain.chat.repository.ChatRoomRepository;
import com.team7.Idam.domain.notification.service.NotificationService;
import com.team7.Idam.domain.user.entity.User;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ChatMessageService {

    private final ChatRoomRepository chatRoomRepository;
    private final ChatMessageRepository chatMessageRepository;
    private final NotificationService notificationService;

    public ChatMessageResponseDto sendMessage(Long roomId, User sender, String content) {
        ChatRoom room = chatRoomRepository.findById(roomId)
                .orElseThrow(() -> new IllegalArgumentException("채팅방이 존재하지 않습니다."));

        Long senderId = sender.getId();
        Long companyId = room.getCompany().getId();
        Long studentId = room.getStudent().getId();

        if (!companyId.equals(senderId) && !studentId.equals(senderId)) {
            throw new SecurityException("채팅방에 참여한 사용자만 메시지를 보낼 수 있습니다.");
        }

        if (room.isDeletedByCompany() && senderId.equals(companyId)) {
            room.setDeletedByCompany(false);
        }
        if (room.isDeletedByStudent() && senderId.equals(studentId)) {
            room.setDeletedByStudent(false);
        }

        ChatMessage message = ChatMessage.builder()
                .chatRoom(room)
                .sender(sender)
                .content(content)
                .build();

        room.updateLastMessage(content);
        chatRoomRepository.save(room);

        ChatMessage savedMessage = chatMessageRepository.save(message);

        User receiver = senderId.equals(companyId)
                ? room.getStudent()
                : room.getCompany();

        notificationService.createNotification(receiver, room, content);

        return ChatMessageResponseDto.from(savedMessage);
    }

    public List<ChatMessageResponseDto> getMessagesByRoom(Long roomId, User user) {
        ChatRoom room = chatRoomRepository.findById(roomId)
                .orElseThrow(() -> new IllegalArgumentException("채팅방이 존재하지 않습니다."));

        Long userId = user.getId();
        Long companyId = room.getCompany().getId();
        Long studentId = room.getStudent().getId();

        if (!companyId.equals(userId) && !studentId.equals(userId)) {
            throw new SecurityException("이 채팅방에 접근할 수 없습니다.");
        }

        boolean deletedForThisUser =
                (companyId.equals(userId) && room.isDeletedByCompany()) ||
                        (studentId.equals(userId) && room.isDeletedByStudent());

        if (deletedForThisUser) {
            throw new SecurityException("삭제된 채팅방입니다.");
        }

        return chatMessageRepository.findByChatRoomOrderBySentAtAsc(room).stream()
                .map(ChatMessageResponseDto::from)
                .collect(Collectors.toList());
    }

    @Transactional
    public void markMessagesAsRead(Long roomId, User reader) {
        ChatRoom room = chatRoomRepository.findById(roomId)
                .orElseThrow(() -> new IllegalArgumentException("채팅방이 존재하지 않습니다."));

        long count = chatMessageRepository.findByChatRoomOrderBySentAtAsc(room).stream()
                .filter(m -> !m.getSender().getId().equals(reader.getId()) && !m.isRead())
                .peek(m -> {
                    m.markAsRead();
                    System.out.println("📖 읽음 처리된 메시지 ID: " + m.getId());
                })
                .count();

        System.out.println("✅ 총 " + count + "개의 메시지 read=true 처리됨");
    }
}
