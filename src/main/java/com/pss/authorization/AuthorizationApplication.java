package com.pss.authorization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Authorization Service Application
 * 
 * Provides RBAC, ABAC, and Hybrid authorization with:
 * - < 5ms latency target for authorization checks
 * - Two-level caching (Caffeine L1 + Redis L2)
 * - gRPC for high-performance authorization
 * - REST for management operations
 */
@SpringBootApplication
@EnableCaching
@EnableAsync
public class AuthorizationApplication {

    static void main(String[] args) {
        SpringApplication.run(AuthorizationApplication.class, args);
    }
}
