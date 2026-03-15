package com.pss.authorization.domain.dto;

import lombok.Builder;

import java.util.HashMap;
import java.util.Map;

/**
 * Authorization request containing all information needed for access decision.
 * Optimized for minimal allocations and fast serialization.
 */
@Builder(toBuilder = true)
public record AuthorizationRequest(
        String tenantId,
        String subjectId,
        String externalSubjectId,
        String resource,
        String action,
        String resourceId,
        Map<String, Object> subjectAttributes,
        Map<String, Object> resourceAttributes,
        Map<String, Object> environmentAttributes,
        Map<String, String> context,
        String correlationId,
        Boolean verbose) {
    public AuthorizationRequest {
        if (subjectAttributes == null)
            subjectAttributes = new HashMap<>();
        if (resourceAttributes == null)
            resourceAttributes = new HashMap<>();
        if (environmentAttributes == null)
            environmentAttributes = new HashMap<>();
        if (context == null)
            context = new HashMap<>();
        if (verbose == null)
            verbose = false;
    }
}
