package com.example.backend.service;

import com.example.backend.config.JwtTokenProvider;
import com.example.backend.domain.User;
import com.example.backend.dto.LoginResponse;
import com.example.backend.dto.UserRegisterRequestDto;
import com.example.backend.repository.UserRepository;
import com.example.backend.util.ErrorCode; // 이전에 정의한 Enum
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder passwordEncoder;
  private final JwtTokenProvider jwtTokenProvider;

  @Transactional
  public LoginResponse signup(UserRegisterRequestDto dto) {
    // 1. 중복 이메일 체크 (명세서: AUTH_EMAIL_ALREADY_EXISTS)
    userRepository.findByEmail(dto.getEmail()).ifPresent(user -> {
      throw new RuntimeException("AUTH_EMAIL_ALREADY_EXISTS");
    });

    // 2. 일반 회원 저장 (표시명 = name)
    User user = User.builder()
            .email(dto.getEmail())
            .password(passwordEncoder.encode(dto.getPassword()))
            .name(dto.getName()) // 닉네임/표시명
            .provider("local")   // 소셜과 구분
            .providerId(dto.getEmail()) // 일반 가입은 이메일을 식별자로 사용
            .build();
    userRepository.save(user);

    // 3. 가입 즉시 로그인 처리 (토큰 발급)
    return login(dto.getEmail(), dto.getPassword());
  }

  @Transactional(readOnly = true)
  public LoginResponse login(String email, String password) {
    // 1. 유저 존재 여부 확인
    User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new RuntimeException("AUTH_INVALID_CREDENTIAL"));

    // 2. 소셜 유저가 일반 로그인을 시도하는지 확인
    if ("google".equals(user.getProvider()) || "kakao".equals(user.getProvider())) {
      throw new RuntimeException("AUTH_SOCIAL_USER_EXISTS"); // 소셜 계정임을 안내 (선택사항)
    }

    // 3. 비밀번호 검증
    if (!passwordEncoder.matches(password, user.getPassword())) {
      throw new RuntimeException("AUTH_INVALID_CREDENTIAL");
    }

    // 4. JWT 토큰 생성 및 응답 (워크스페이스 정보 포함)
    String token = jwtTokenProvider.createToken(user.getEmail());

    // workspaceCount는 추후 연동 전까지 0으로 전달
    return new LoginResponse(token, user.getEmail(), user.getName(), 0, null);
  }
}