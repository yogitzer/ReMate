package com.example.backend.controller;

import com.example.backend.dto.LoginRequest;
import com.example.backend.dto.LoginResponse;
import com.example.backend.dto.UserRegisterRequestDto;
import com.example.backend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
// 명세서 규격에 따라 v1 경로 추가
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  // 회원가입 API
  @PostMapping("/signup")
  public ResponseEntity<LoginResponse> signup(@RequestBody UserRegisterRequestDto dto) {
    return ResponseEntity.ok(authService.signup(dto));
  }

  // 로그인 API
  @PostMapping("/signin")
  public ResponseEntity<LoginResponse> signin(@RequestBody LoginRequest dto) {
    return ResponseEntity.ok(authService.login(dto.getEmail(), dto.getPassword()));
  }

  /**
   * 401 및 토큰 검증 테스트용 API
   * SecurityConfig에서 이 경로는 .authenticated()로 설정해야 테스트가 가능합니다.
   */
  @GetMapping("/me")
  public ResponseEntity<?> getMyInfo() {
    // 성공 시 공통 응답 규격 테스트 데이터
    Map<String, Object> data = new HashMap<>();
    data.put("email", "test@example.com");
    data.put("name", "인증테스터");
    data.put("status", "Token is Valid");

    Map<String, Object> response = new HashMap<>();
    response.put("success", true);
    response.put("data", data);

    // 메타 데이터 (A 작업자 머지 전 임시 구성)
    Map<String, Object> meta = new HashMap<>();
    meta.put("timestamp", LocalDateTime.now());
    meta.put("traceId", UUID.randomUUID().toString());
    response.put("meta", meta);

    return ResponseEntity.ok(response);
  }
}