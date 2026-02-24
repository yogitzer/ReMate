package com.example.backend.config;

import com.example.backend.util.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        // 1. 정적 리소스 및 기본 에러 경로 허용
                        .requestMatchers(
                                "/", "/index.html", "/signup.html", "/signin.html",
                                "/favicon.ico", "/error", "/css/**", "/js/**", "/static/**"
                        ).permitAll()
                        // 2. 로그인과 회원가입은 토큰 없이도 가능하게 허용 (v1 경로 포함)
                        .requestMatchers("/api/v1/auth/signup", "/api/v1/auth/signin").permitAll()
                        // 3. Swagger 관련 경로 완전 허용
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        // 4. 테스트용 /me 및 워크스페이스는 인증 필요
                        .requestMatchers("/api/v1/auth/me").authenticated()
                        .requestMatchers("/api/v1/workspaces/**").authenticated()
                        // 나머지 모든 요청 인증 필요
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oAuth2SuccessHandler)
                )
                .exceptionHandling(exception -> exception
                        // 비로그인 사용자가 보호된 리소스(ex: /me) 접근 시 401 응답
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(401);
                            response.setContentType("application/json;charset=UTF-8");

                            String json = String.format(
                                    "{\"success\": false, \"error\": {\"code\": \"%s\", \"message\": \"인증이 필요합니다.\"}, \"meta\": {\"timestamp\": \"%s\", \"traceId\": \"%s\"}}",
                                    ErrorCode.AUTH_UNAUTHORIZED.name(), LocalDateTime.now(), UUID.randomUUID().toString()
                            );
                            response.getWriter().write(json);
                        })
                );

        // JWT 필터를 시큐리티 필터 체인에 등록
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // 프론트엔드 도메인 허용
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:5173"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        // 클라이언트에서 Authorization 헤더를 읽을 수 있도록 노출
        configuration.setExposedHeaders(List.of("Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}