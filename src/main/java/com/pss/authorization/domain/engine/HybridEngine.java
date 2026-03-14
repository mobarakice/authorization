package com.pss.authorization.domain.engine;

import com.pss.authorization.cache.TwoLevelCacheManager;
import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.dto.AuthorizationResponse.Decision;
import com.pss.authorization.domain.dto.AuthorizationResponse.EvaluationDetail;
import com.pss.authorization.domain.model.hybrid.AuthorizationContext;
import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import com.pss.authorization.domain.model.hybrid.CombiningStrategy;
import com.pss.authorization.persistence.repository.AuthorizationContextRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Hybrid Authorization Engine combining RBAC and ABAC.
 * 
 * Evaluation Strategy (configurable per resource):
 * - RBAC_FIRST: Check RBAC, if permitted check ABAC
 * - ABAC_FIRST: Check ABAC, if permitted check RBAC
 * - AND: Both must permit
 * - OR: Either can permit
 * - RBAC_REQUIRED_ABAC_CONSTRAINS: RBAC must permit, ABAC adds constraints
 * 
 * Target latency: < 5ms (combining both engines)
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class HybridEngine implements AuthorizationEngine {

    private final RbacEngine rbacEngine;
    private final AbacEngine abacEngine;
    private final TwoLevelCacheManager cacheManager;
    private final AuthorizationContextRepository contextRepository;

    @Override
    public String getEngineType() {
        return "HYBRID";
    }

    @Override
    public boolean canHandle(AuthorizationRequest request) {
        return rbacEngine.canHandle(request) && abacEngine.canHandle(request);
    }

    @Override
    public AuthorizationResponse evaluate(AuthorizationRequest request) {
        long startTime = System.nanoTime();
        List<EvaluationDetail> details = new ArrayList<>();

        try {
            // Step 1: Determine which strategy to use for this resource
            CombiningStrategy strategy = getStrategy(request);

            // Step 2: Execute based on strategy
            Decision finalDecision = switch (strategy) {
                case RBAC_FIRST -> evaluateRbacFirst(request, details);
                case ABAC_FIRST -> evaluateAbacFirst(request, details);
                case AND -> evaluateAnd(request, details);
                case OR -> evaluateOr(request, details);
                case RBAC_REQUIRED_ABAC_CONSTRAINS -> evaluateRbacRequiredAbacConstrains(request, details);
                case ABAC_PRIMARY_RBAC_FALLBACK -> evaluateAbacPrimaryRbacFallback(request, details);
            };

            return buildResponse(finalDecision, strategy, details, startTime,
                    Boolean.TRUE.equals(request.getVerbose()));

        } catch (Exception e) {
            log.error("Hybrid evaluation error", e);
            return buildResponse(Decision.INDETERMINATE, null, details, startTime,
                    Boolean.TRUE.equals(request.getVerbose()));
        }
    }

    /**
     * Gets the combining strategy for this request.
     * Checks authorization context configuration.
     */
    private CombiningStrategy getStrategy(AuthorizationRequest request) {
        Optional<AuthorizationContext> contextOpt = cacheManager.getAuthorizationContext(
                request.getTenantId(), request.getResource());

        if (contextOpt.isEmpty()) {
            // Try loading from DB
            List<AuthorizationContext> contexts = contextRepository.findMatchingContexts(
                    request.getTenantId(), request.getResource());

            if (!contexts.isEmpty()) {
                AuthorizationContext context = contexts.get(0);
                // Cache for future requests
                cacheManager.putAuthorizationContext(
                        request.getTenantId(), request.getResource(), context);
                return context.getCombiningStrategy() != null
                        ? context.getCombiningStrategy()
                        : CombiningStrategy.AND;
            }
        } else {
            return contextOpt.get().getCombiningStrategy();
        }

        // Default strategy
        return CombiningStrategy.AND;
    }

    /**
     * RBAC_FIRST: Check RBAC first, if permit then check ABAC.
     */
    private Decision evaluateRbacFirst(AuthorizationRequest request, List<EvaluationDetail> details) {
        // RBAC check
        AuthorizationResponse rbacResult = rbacEngine.evaluate(request);
        details.add(toDetail("RBAC", rbacResult));

        if (rbacResult.getDecision() == Decision.DENY) {
            return Decision.DENY; // Short-circuit
        }

        if (rbacResult.getDecision() == Decision.PERMIT) {
            // ABAC check
            AuthorizationResponse abacResult = abacEngine.evaluate(request);
            details.add(toDetail("ABAC", abacResult));

            return abacResult.getDecision() == Decision.DENY ? Decision.DENY : Decision.PERMIT;
        }

        return Decision.NOT_APPLICABLE;
    }

    /**
     * ABAC_FIRST: Check ABAC first, if permit then check RBAC.
     */
    private Decision evaluateAbacFirst(AuthorizationRequest request, List<EvaluationDetail> details) {
        // ABAC check
        AuthorizationResponse abacResult = abacEngine.evaluate(request);
        details.add(toDetail("ABAC", abacResult));

        if (abacResult.getDecision() == Decision.DENY) {
            return Decision.DENY; // Short-circuit
        }

        if (abacResult.getDecision() == Decision.PERMIT) {
            // RBAC check
            AuthorizationResponse rbacResult = rbacEngine.evaluate(request);
            details.add(toDetail("RBAC", rbacResult));

            return rbacResult.getDecision() == Decision.DENY ? Decision.DENY : Decision.PERMIT;
        }

        // ABAC not applicable, fall back to RBAC
        AuthorizationResponse rbacResult = rbacEngine.evaluate(request);
        details.add(toDetail("RBAC", rbacResult));
        return rbacResult.getDecision();
    }

    /**
     * AND: Both RBAC and ABAC must permit.
     */
    private Decision evaluateAnd(AuthorizationRequest request, List<EvaluationDetail> details) {
        AuthorizationResponse rbacResult = rbacEngine.evaluate(request);
        details.add(toDetail("RBAC", rbacResult));

        AuthorizationResponse abacResult = abacEngine.evaluate(request);
        details.add(toDetail("ABAC", abacResult));

        if (rbacResult.getDecision() == Decision.DENY || abacResult.getDecision() == Decision.DENY) {
            return Decision.DENY;
        }

        if (rbacResult.getDecision() == Decision.PERMIT && abacResult.getDecision() == Decision.PERMIT) {
            return Decision.PERMIT;
        }

        // Handle NOT_APPLICABLE cases
        if (rbacResult.getDecision() == Decision.PERMIT && abacResult.getDecision() == Decision.NOT_APPLICABLE) {
            return Decision.PERMIT; // ABAC has no opinion
        }
        if (abacResult.getDecision() == Decision.PERMIT && rbacResult.getDecision() == Decision.NOT_APPLICABLE) {
            return Decision.DENY; // RBAC required but not granted
        }

        return Decision.NOT_APPLICABLE;
    }

    /**
     * OR: Either RBAC or ABAC can permit.
     */
    private Decision evaluateOr(AuthorizationRequest request, List<EvaluationDetail> details) {
        AuthorizationResponse rbacResult = rbacEngine.evaluate(request);
        details.add(toDetail("RBAC", rbacResult));

        if (rbacResult.getDecision() == Decision.PERMIT) {
            return Decision.PERMIT; // RBAC permits, done
        }

        AuthorizationResponse abacResult = abacEngine.evaluate(request);
        details.add(toDetail("ABAC", abacResult));

        if (abacResult.getDecision() == Decision.PERMIT) {
            return Decision.PERMIT; // ABAC permits
        }

        // Neither permits
        if (rbacResult.getDecision() == Decision.DENY || abacResult.getDecision() == Decision.DENY) {
            return Decision.DENY;
        }

        return Decision.NOT_APPLICABLE;
    }

    /**
     * RBAC_REQUIRED_ABAC_CONSTRAINS: RBAC must permit, ABAC adds constraints.
     */
    private Decision evaluateRbacRequiredAbacConstrains(AuthorizationRequest request, List<EvaluationDetail> details) {
        AuthorizationResponse rbacResult = rbacEngine.evaluate(request);
        details.add(toDetail("RBAC", rbacResult));

        if (rbacResult.getDecision() != Decision.PERMIT) {
            return Decision.DENY; // RBAC required
        }

        // RBAC permits, check ABAC constraints
        AuthorizationResponse abacResult = abacEngine.evaluate(request);
        details.add(toDetail("ABAC", abacResult));

        // ABAC can only deny or not apply (NOT grant additional permissions)
        if (abacResult.getDecision() == Decision.DENY) {
            return Decision.DENY;
        }

        return Decision.PERMIT;
    }

    /**
     * ABAC_PRIMARY_RBAC_FALLBACK: Use ABAC if policies exist, otherwise RBAC.
     */
    private Decision evaluateAbacPrimaryRbacFallback(AuthorizationRequest request, List<EvaluationDetail> details) {
        AuthorizationResponse abacResult = abacEngine.evaluate(request);
        details.add(toDetail("ABAC", abacResult));

        if (abacResult.getDecision() != Decision.NOT_APPLICABLE) {
            return abacResult.getDecision();
        }

        // No ABAC policies, fallback to RBAC
        AuthorizationResponse rbacResult = rbacEngine.evaluate(request);
        details.add(toDetail("RBAC", rbacResult));
        return rbacResult.getDecision();
    }

    private EvaluationDetail toDetail(String evaluator, AuthorizationResponse response) {
        return EvaluationDetail.builder()
                .evaluator(evaluator)
                .result(response.getDecision())
                .reason(response.getReason())
                .durationMs(response.getEvaluationTimeMs())
                .build();
    }

    private AuthorizationResponse buildResponse(
            Decision decision,
            CombiningStrategy strategy,
            List<EvaluationDetail> details,
            long startTimeNanos,
            boolean verbose) {

        double evaluationTimeMs = (System.nanoTime() - startTimeNanos) / 1_000_000.0;

        AuthorizationResponse.AuthorizationResponseBuilder builder = AuthorizationResponse.builder()
                .decision(decision)
                .mode(AuthorizationMode.HYBRID)
                .reason("Hybrid evaluation with strategy: " + (strategy != null ? strategy : "default"))
                .determinedBy("Hybrid Engine")
                .evaluationTimeMs(evaluationTimeMs);

        if (verbose) {
            builder.evaluationDetails(details);
        }

        return builder.build();
    }
}
