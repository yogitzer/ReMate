package com.example.backend.util;

public enum ErrorCode {
    AUTH_INVALID_CREDENTIAL,    // 로그인 실패 (비밀번호 불일치 등)
    AUTH_EMAIL_ALREADY_EXISTS,  // 중복 가입 시도
    AUTH_UNAUTHORIZED           // 토큰 만료 등 인증 실패
}