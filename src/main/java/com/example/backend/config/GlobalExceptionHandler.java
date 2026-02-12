package com.example.backend.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException e) {
        Map<String, Object> response = new HashMap<>();
        String errorCode = e.getMessage(); // 예: "AUTH_INVALID_CREDENTIAL"

        response.put("code", errorCode);

        // 에러 코드별 메시지 및 상태 코드 매핑
        switch (errorCode) {
            case "AUTH_EMAIL_ALREADY_EXISTS":
                response.put("message", "이미 사용 중인 이메일입니다.");
                return ResponseEntity.status(HttpStatus.CONFLICT).body(response); // 409

            case "AUTH_INVALID_CREDENTIAL":
                response.put("message", "이메일 또는 비밀번호가 일치하지 않습니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response); // 401

            case "AUTH_UNAUTHORIZED":
                response.put("message", "인증이 필요한 서비스입니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response); // 401

            default:
                // 우리가 정의하지 않은 에러는 500으로 처리
                response.put("code", "INTERNAL_SERVER_ERROR");
                response.put("message", "서버 내부 오류가 발생했습니다.");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}