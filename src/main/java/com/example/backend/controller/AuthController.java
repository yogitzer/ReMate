package com.example.backend.controller;

import com.example.backend.dto.LoginRequest;
import com.example.backend.dto.LoginResponse;
import com.example.backend.dto.UserRegisterRequestDto;
import com.example.backend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
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
    // AuthService에 이미 구현된 login(email, password)을 호출합니다.
    return ResponseEntity.ok(authService.login(dto.getEmail(), dto.getPassword()));
  }
}