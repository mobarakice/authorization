package com.pss.authorization.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI/Swagger configuration for API documentation.
 * 
 * Access Swagger UI at: http://localhost:8080/swagger-ui.html
 * Access OpenAPI spec at: http://localhost:8080/v3/api-docs
 */
@Configuration
public class OpenApiConfig {

    @Value("${spring.application.name:Authorization Service}")
    private String applicationName;

    @Bean
    public OpenAPI authorizationServiceOpenAPI() {
        return new OpenAPI()
                .info(apiInfo())
                .servers(List.of(
                        new Server()
                                .url("http://localhost:8080")
                                .description("Local Development Server"),
                        new Server()
                                .url("https://api.example.com")
                                .description("Production Server")))
                .tags(List.of(
                        new Tag()
                                .name("Authorization")
                                .description("Authorization check endpoints - Target latency: < 5ms"),
                        new Tag()
                                .name("Role Management")
                                .description("CRUD operations for roles"),
                        new Tag()
                                .name("Policy Management")
                                .description("CRUD operations for ABAC policies"),
                        new Tag()
                                .name("Subject Management")
                                .description("Subject and role assignment management")))
                .components(new Components()
                        .addSecuritySchemes("tenant-id", new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("X-Tenant-ID")
                                .description("Tenant identifier for multi-tenancy"))
                        .addSecuritySchemes("subject-id", new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("X-Subject-ID")
                                .description("Subject/User identifier"))
                        .addSecuritySchemes("bearer-jwt", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT Bearer token for authentication")))
                .addSecurityItem(new SecurityRequirement().addList("tenant-id"));
    }

    private Info apiInfo() {
        return new Info()
                .title("Authorization Service API")
                .description("""
                        High-performance Authorization Service supporting:

                        - **RBAC** (Role-Based Access Control) with O(1) permission bitmap lookups
                        - **ABAC** (Attribute-Based Access Control) with policy evaluation
                        - **Hybrid** authorization combining both models

                        ### Performance Target
                        All authorization checks are optimized for **< 5ms latency** using:
                        - Two-level caching (Caffeine L1 + Redis L2)
                        - Permission bitmaps for O(1) lookups
                        - Materialized role hierarchies

                        ### Multi-Tenancy
                        All operations require the `X-Tenant-ID` header for data isolation.
                        """)
                .version("1.0.0")
                .contact(new Contact()
                        .name("PSS Team")
                        .email("support@pss.com")
                        .url("https://pss.com"))
                .license(new License()
                        .name("Apache 2.0")
                        .url("https://www.apache.org/licenses/LICENSE-2.0"));
    }
}
