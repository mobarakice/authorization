package com.pss.authorization.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

/**
 * Authorization request containing all information needed for access decision.
 * Optimized for minimal allocations and fast serialization.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthorizationRequest {

    /**
     * Tenant identifier for multi-tenancy.
     */
    private String tenantId;

    /**
     * Subject identifier (user ID, service account ID).
     */
    private String subjectId;

    /**
     * External subject identifier (e.g., JWT sub claim).
     */
    private String externalSubjectId;

    /**
     * Resource being accessed (e.g., "orders", "users:123").
     */
    private String resource;

    /**
     * Action being performed (e.g., "READ", "WRITE", "DELETE").
     */
    private String action;

    /**
     * Optional resource instance ID for instance-level access control.
     */
    private String resourceId;

    /**
     * Subject attributes for ABAC evaluation.
     * Populated from JWT claims, headers, or context.
     */
    @Builder.Default
    private Map<String, Object> subjectAttributes = new HashMap<>();

    /**
     * Resource attributes for ABAC evaluation.
     */
    @Builder.Default
    private Map<String, Object> resourceAttributes = new HashMap<>();

    /**
     * Environment attributes (time, IP, location, etc.).
     */
    @Builder.Default
    private Map<String, Object> environmentAttributes = new HashMap<>();

    /**
     * Additional context for logging and debugging.
     */
    @Builder.Default
    private Map<String, String> context = new HashMap<>();

    /**
     * Correlation ID for request tracing.
     */
    private String correlationId;

    /**
     * Whether to include detailed evaluation info in response.
     */
    @Builder.Default
    private Boolean verbose = false;
}
