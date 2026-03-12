package com.pss.authorization.domain.dto;

import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Authorization decision result.
 * Contains the decision, reason, and optional evaluation details.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthorizationResponse {

    /**
     * The authorization decision.
     */
    private Decision decision;

    /**
     * Authorization mode used for this decision.
     */
    private AuthorizationMode mode;

    /**
     * Human-readable reason for the decision.
     */
    private String reason;

    /**
     * Specific policy or role that determined the decision.
     */
    private String determinedBy;

    /**
     * Evaluation duration in milliseconds.
     */
    private double evaluationTimeMs;

    /**
     * Whether the decision was served from cache.
     */
    @Builder.Default
    private boolean cached = false;

    /**
     * Cache level if cached: L1 (Caffeine) or L2 (Redis).
     */
    private String cacheLevel;

    /**
     * Correlation ID from the request.
     */
    private String correlationId;

    /**
     * Timestamp of the decision.
     */
    @Builder.Default
    private Instant timestamp = Instant.now();

    /**
     * Detailed evaluation info (only if verbose=true in request).
     */
    @Builder.Default
    private List<EvaluationDetail> evaluationDetails = new ArrayList<>();

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
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class EvaluationDetail {
        private String evaluator; // RBAC, ABAC, POLICY_NAME
        private Decision result;
        private String reason;
        private double durationMs;
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
