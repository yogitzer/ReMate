package com.example.backend.config; // 패키지명은 기원님 프로젝트에 맞게 수정!

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI() {
        // 1. 보안 스키마 이름 설정
        String securityJwtName = "bearerAuth";

        // 2. 모든 API에 보안 설정 적용 (자물쇠 아이콘 생성)
        SecurityRequirement securityRequirement = new SecurityRequirement().addList(securityJwtName);

        // 3. JWT 인증 방식 정의 (Bearer 방식)
        Components components = new Components().addSecuritySchemes(securityJwtName, new SecurityScheme()
                .name(securityJwtName)
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT"));

        return new OpenAPI()
                .info(new Info()
                        .title("우리 프로젝트 API 명세서")
                        .description("인증 관련 API 및 공통 응답 테스트")
                        .version("v1.0.0"))
                .addSecurityItem(securityRequirement)
                .components(components);
    }
}