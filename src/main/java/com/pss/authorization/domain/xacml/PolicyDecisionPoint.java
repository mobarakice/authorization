package com.pss.authorization.domain.xacml;

import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.engine.AbacEngine;
import com.pss.authorization.domain.engine.HybridEngine;
import com.pss.authorization.domain.engine.RbacEngine;
import com.pss.authorization.domain.model.hybrid.AuthorizationContext;
import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import com.pss.authorization.persistence.repository.AuthorizationContextRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Policy Decision Point (PDP) - Central authorization decision maker.
 * 
 * Routes authorization requests to the appropriate engine based on:
 * 1. Explicit mode in request
 * 2. Authorization context configuration for the resource
 * 3. Default mode (RBAC)
 * 
 * This is the main entry point for all authorization checks.
 * Target latency: < 5ms
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PolicyDecisionPoint {

    private final RbacEngine rbacEngine;
    private final AbacEngine abacEngine;
    private final HybridEngine hybridEngine;
    private final AuthorizationContextRepository contextRepository;

    /**
     * Evaluates an authorization request and returns a decision.
     *
     * @param request The authorization request
     * @return The authorization decision
     */
    public AuthorizationResponse evaluate(AuthorizationRequest request) {
        long startTime = System.nanoTime();

        // Add correlation ID if not present
        if (request.getCorrelationId() == null) {
            request.setCorrelationId(UUID.randomUUID().toString());
        }

        log.debug("PDP evaluating request: subject={}, resource={}, action={}, correlationId={}",
                request.getExternalSubjectId(),
                request.getResource(),
                request.getAction(),
                request.getCorrelationId());

        AuthorizationResponse response = doEvaluate(request);

        // Set correlation ID in response
        response.setCorrelationId(request.getCorrelationId());

        double totalTimeMs = (System.nanoTime() - startTime) / 1_000_000.0;

        log.debug("PDP decision: {} in {}ms (correlationId={})",
                response.getDecision(),
                String.format("%.2f", totalTimeMs),
                request.getCorrelationId());

        // Warn if exceeding target latency
        if (totalTimeMs > 5.0) {
            log.warn("Authorization check exceeded 5ms target: {}ms (correlationId={})",
                    String.format("%.2f", totalTimeMs),
                    request.getCorrelationId());
        }

        return response;
    }

    /**
     * Evaluates multiple authorization requests in batch.
     * More efficient for checking multiple permissions at once.
     */
    public List<AuthorizationResponse> evaluateBatch(List<AuthorizationRequest> requests) {
        return requests.stream()
                .map(this::evaluate)
                .toList();
    }

    /**
     * Quick check if access is permitted (convenience method).
     */
    public boolean isPermitted(AuthorizationRequest request) {
        return evaluate(request).isPermitted();
    }

    /**
     * Quick check if access is permitted with minimal parameters.
     */
    public boolean isPermitted(String tenantId, String subjectId, String resource, String action) {
        AuthorizationRequest request = AuthorizationRequest.builder()
                .tenantId(tenantId)
                .externalSubjectId(subjectId)
                .resource(resource)
                .action(action)
                .build();
        return isPermitted(request);
    }

    private AuthorizationResponse doEvaluate(AuthorizationRequest request) {
        // Determine authorization mode
        AuthorizationMode mode = determineMode(request);

        return switch (mode) {
            case RBAC -> rbacEngine.evaluate(request);
            case ABAC -> abacEngine.evaluate(request);
            case HYBRID -> hybridEngine.evaluate(request);
        };
    }

    /**
     * Determines which authorization mode to use.
     */
    private AuthorizationMode determineMode(AuthorizationRequest request) {
        // Check if resource has specific configuration
        List<AuthorizationContext> contexts = contextRepository.findMatchingContexts(
                request.getTenantId(),
                request.getResource());

        if (!contexts.isEmpty()) {
            return contexts.get(0).getMode();
        }

        // Default to RBAC for simple permission checks
        // Use HYBRID if attributes are provided
        if (hasAttributes(request)) {
            return AuthorizationMode.HYBRID;
        }

        return AuthorizationMode.RBAC;
    }

    private boolean hasAttributes(AuthorizationRequest request) {
        return (request.getSubjectAttributes() != null && !request.getSubjectAttributes().isEmpty())
                || (request.getResourceAttributes() != null && !request.getResourceAttributes().isEmpty())
                || (request.getEnvironmentAttributes() != null && !request.getEnvironmentAttributes().isEmpty());
    }
}
