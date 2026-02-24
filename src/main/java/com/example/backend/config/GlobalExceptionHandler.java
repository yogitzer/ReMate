package com.example.backend.config;

import com.example.backend.util.ErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException e) {
        // 에러 메시지가 Enum 이름과 일치한다고 가정 (예: throw new RuntimeException("AUTH_INVALID_CREDENTIAL"))
        String errorName = e.getMessage();
        ErrorCode errorCode;

        try {
            errorCode = ErrorCode.valueOf(errorName);
        } catch (Exception ex) {
            // 정의되지 않은 에러일 경우 기본값 처리
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", "서버 내부 오류가 발생했습니다.");
        }

        // Enum별 메시지 및 상태 코드 매핑
        switch (errorCode) {
            case AUTH_EMAIL_ALREADY_EXISTS:
                return buildErrorResponse(HttpStatus.CONFLICT, errorCode.name(), "이미 사용 중인 이메일입니다.");
            case AUTH_INVALID_CREDENTIAL:
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, errorCode.name(), "이메일 또는 비밀번호가 일치하지 않습니다.");
            case AUTH_UNAUTHORIZED:
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, errorCode.name(), "인증 정보가 유효하지 않습니다.");
            default:
                return buildErrorResponse(HttpStatus.BAD_REQUEST, errorCode.name(), "잘못된 요청입니다.");
        }
    }

    // 명세서 규격 { success, error, meta } 생성을 위한 공통 메서드
    private ResponseEntity<Map<String, Object>> buildErrorResponse(HttpStatus status, String code, String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);

        Map<String, String> error = new HashMap<>();
        error.put("code", code);
        error.put("message", message);
        response.put("error", error);

        Map<String, Object> meta = new HashMap<>();
        meta.put("timestamp", LocalDateTime.now());
        meta.put("traceId", UUID.randomUUID().toString()); // 나중에 공통 traceId 필터 도입 시 교체
        response.put("meta", meta);

        return ResponseEntity.status(status).body(response);
    }
}