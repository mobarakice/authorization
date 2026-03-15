package com.pss.authorization.domain.dto;

import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import lombok.Builder;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Authorization decision result.
 * Contains the decision, reason, and optional evaluation details.
 */
@Builder(toBuilder = true)
public record AuthorizationResponse(
        Decision decision,
        AuthorizationMode mode,
        String reason,
        String determinedBy,
        double evaluationTimeMs,
        boolean cached,
        String cacheLevel,
        String correlationId,
        Instant timestamp,
        List<EvaluationDetail> evaluationDetails) {
    public AuthorizationResponse {
        if (timestamp == null)
            timestamp = Instant.now();
        if (evaluationDetails == null)
            evaluationDetails = new ArrayList<>();
    }

    /**
     * Possible authorization decisions.
     */
    public enum Decision {
        /**
         * Access is permitted.
         */
        PERMIT,

        /**
         * Access is denied.
         */
        DENY,

        /**
         * No applicable policy found; use default.
         */
        NOT_APPLICABLE,

        /**
         * Evaluation error occurred.
         */
        INDETERMINATE
    }

    /**
     * Detailed info about a single evaluation step.
     */
    /**
     * Detailed info about a single evaluation step.
     */
    @Builder
    public record EvaluationDetail(
            String evaluator, // RBAC, ABAC, POLICY_NAME
            Decision result,
            String reason,
            double durationMs) {
    }

    /**
     * Creates a PERMIT response.
     */
    public static AuthorizationResponse permit(String reason) {
        return AuthorizationResponse.builder()
                .decision(Decision.PERMIT)
                .reason(reason)
                .build();
    }

    /**
     * Creates a DENY response.
     */
    public static AuthorizationResponse deny(String reason) {
        return AuthorizationResponse.builder()
                .decision(Decision.DENY)
                .reason(reason)
                .build();
    }

    /**
     * Checks if access is permitted.
     */
    public boolean isPermitted() {
        return decision == Decision.PERMIT;
    }
}
