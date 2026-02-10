package com.example.backend.controller;

import com.example.backend.dto.LoginResponse;
import com.example.backend.dto.UserRegisterRequestDto;
import com.example.backend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  @PostMapping("/signup")
  public ResponseEntity<?> signup(@RequestBody UserRegisterRequestDto dto) {
    try {
      LoginResponse response = authService.signup(dto);
      return ResponseEntity.ok(response);
    } catch (RuntimeException e) {
      return ResponseEntity.badRequest().body(Map.of("code", e.getMessage()));
    }
  }

  @PostMapping("/signin")
  public ResponseEntity<?> signin(@RequestBody Map<String, String> body) {
    try {
      LoginResponse response = authService.login(body.get("email"), body.get("password"));
      return ResponseEntity.ok(response);
    } catch (RuntimeException e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("code", e.getMessage()));
    }
  }
}