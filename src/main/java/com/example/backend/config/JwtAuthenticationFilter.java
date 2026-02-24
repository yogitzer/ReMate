package com.example.backend.config;

import com.example.backend.util.ErrorCode;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // 1. 로그인, 회원가입, 스웨거 등 인증이 필요 없는 경로는 필터 로직을 건너뜁니다.
        if (path.startsWith("/api/v1/auth/signup") ||
                path.startsWith("/api/v1/auth/signin") ||
                path.startsWith("/v3/api-docs") ||
                path.startsWith("/swagger-ui")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");

        // 2. Authorization 헤더가 있는 경우 토큰 검증
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                if (jwtTokenProvider.validateToken(token)) {
                    String email = jwtTokenProvider.getSubject(token);
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            email, null, Collections.emptyList());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } catch (ExpiredJwtException e) {
                // 토큰 만료 시 공통 에러 규격 응답 후 종료
                sendErrorResponse(response, ErrorCode.AUTH_UNAUTHORIZED, "토큰이 만료되었습니다.");
                return;
            } catch (Exception e) {
                // 기타 인증 실패 시 공통 에러 규격 응답 후 종료
                sendErrorResponse(response, ErrorCode.AUTH_UNAUTHORIZED, "인증에 실패했습니다.");
                return;
            }
        }

        // 3. 토큰이 없더라도 permitAll 된 경로일 수 있으므로 다음 필터로 진행
        filterChain.doFilter(request, response);
    }

    private void sendErrorResponse(HttpServletResponse response, ErrorCode errorCode, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");

        // 명세서 규격: { success, error: { code, message }, meta }
        String json = String.format(
                "{\"success\": false, \"error\": {\"code\": \"%s\", \"message\": \"%s\"}, \"meta\": {\"timestamp\": \"%s\", \"traceId\": \"%s\"}}",
                errorCode.name(), message, LocalDateTime.now(), UUID.randomUUID().toString()
        );

        response.getWriter().write(json);
    }
}