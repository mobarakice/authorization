package com.pss.authorization.domain.engine;

import com.pss.authorization.cache.TwoLevelCacheManager;
import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.dto.AuthorizationResponse.Decision;
import com.pss.authorization.domain.model.abac.*;
import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import com.pss.authorization.persistence.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.regex.Pattern;

/**
 * ABAC (Attribute-Based Access Control) Engine.
 * 
 * Evaluation Strategy:
 * 1. Find applicable policies for resource:action
 * 2. For each policy, evaluate all rules and conditions
 * 3. Apply combining algorithm to determine final decision
 * 
 * Target latency: < 3ms
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AbacEngine implements AuthorizationEngine {

    private final TwoLevelCacheManager cacheManager;
    private final PolicyRepository policyRepository;

    // Pre-compiled regex cache
    private final Map<String, Pattern> regexCache = new HashMap<>();

    @Override
    public String getEngineType() {
        return "ABAC";
    }

    @Override
    public boolean canHandle(AuthorizationRequest request) {
        return request.getTenantId() != null &&
                request.getResource() != null &&
                request.getAction() != null;
    }

    @Override
    public AuthorizationResponse evaluate(AuthorizationRequest request) {
        long startTime = System.nanoTime();

        try {
            String tenantId = request.getTenantId();
            String resource = request.getResource();
            String action = request.getAction();

            // Step 1: Get applicable policies from cache or DB
            List<Policy> policies = getApplicablePolicies(tenantId, resource, action);

            if (policies.isEmpty()) {
                return buildResponse(Decision.NOT_APPLICABLE,
                        "No applicable ABAC policies found",
                        startTime, null);
            }

            // Step 2: Evaluate each policy
            List<PolicyEvaluationResult> results = new ArrayList<>();
            for (Policy policy : policies) {
                PolicyEvaluationResult result = evaluatePolicy(policy, request);
                results.add(result);

                // Short-circuit if FIRST_APPLICABLE
                if (policy.getCombiningAlgorithm() == CombiningAlgorithm.FIRST_APPLICABLE
                        && result.decision != Decision.NOT_APPLICABLE) {
                    break;
                }
            }

            // Step 3: Apply combining algorithm
            Decision finalDecision = applyCombiningAlgorithm(results, CombiningAlgorithm.DENY_OVERRIDES);
            String determinedBy = results.stream()
                    .filter(r -> r.decision == finalDecision)
                    .map(r -> r.policyName)
                    .findFirst()
                    .orElse("Default Policy");

            return buildResponse(finalDecision,
                    "ABAC evaluation complete: " + finalDecision,
                    startTime, determinedBy);

        } catch (Exception e) {
            log.error("ABAC evaluation error", e);
            return buildResponse(Decision.INDETERMINATE,
                    "Evaluation error: " + e.getMessage(),
                    startTime, null);
        }
    }

    /**
     * Gets applicable policies from cache or database.
     */
    private List<Policy> getApplicablePolicies(String tenantId, String resource, String action) {
        Optional<List<Policy>> cached = cacheManager.getPoliciesByTarget(tenantId, resource, action);
        if (cached.isPresent()) {
            return cached.get();
        }

        List<Policy> policies = policyRepository.findApplicablePolicies(tenantId, resource, action);
        cacheManager.putPoliciesByTarget(tenantId, resource, action, policies);
        return policies;
    }

    /**
     * Evaluates a single policy against the request.
     */
    private PolicyEvaluationResult evaluatePolicy(Policy policy, AuthorizationRequest request) {
        // Check if policy targets this request
        if (!policy.matchesTarget(request.getResource(), request.getAction())) {
            return new PolicyEvaluationResult(policy.getName(), Decision.NOT_APPLICABLE, "Target mismatch");
        }

        // Evaluate all rules
        boolean allRulesMatch = true;
        for (PolicyRule rule : policy.getRules()) {
            if (!rule.isActive())
                continue;

            boolean ruleMatch = evaluateRule(rule, request);

            if ("AND".equals(rule.getConditionLogic())) {
                allRulesMatch = allRulesMatch && ruleMatch;
            } else { // OR
                if (ruleMatch) {
                    allRulesMatch = true;
                    break;
                }
            }
        }

        if (allRulesMatch) {
            Decision decision = policy.getEffect() == PolicyEffect.PERMIT ? Decision.PERMIT : Decision.DENY;
            return new PolicyEvaluationResult(policy.getName(), decision, "Rules matched");
        } else {
            return new PolicyEvaluationResult(policy.getName(), Decision.NOT_APPLICABLE, "Rules not matched");
        }
    }

    /**
     * Evaluates a single rule against the request.
     */
    private boolean evaluateRule(PolicyRule rule, AuthorizationRequest request) {
        List<Boolean> conditionResults = new ArrayList<>();

        for (RuleCondition condition : rule.getConditions()) {
            boolean result = evaluateCondition(condition, request);
            if (condition.isNegate()) {
                result = !result;
            }
            conditionResults.add(result);
        }

        if ("AND".equals(rule.getConditionLogic())) {
            return conditionResults.stream().allMatch(Boolean::booleanValue);
        } else { // OR
            return conditionResults.stream().anyMatch(Boolean::booleanValue);
        }
    }

    /**
     * Evaluates a single condition.
     */
    private boolean evaluateCondition(RuleCondition condition, AuthorizationRequest request) {
        AttributeDefinition attrDef = condition.getAttribute();
        Object actualValue = getAttributeValue(attrDef, request);
        String expectedValue = condition.getExpectedValue();
        ConditionOperator operator = condition.getOperator();

        if (actualValue == null) {
            return operator == ConditionOperator.IS_NULL;
        }

        return evaluateOperator(operator, actualValue, expectedValue,
                condition.getExpectedValue2(), attrDef.getDataType());
    }

    /**
     * Gets attribute value from the request based on attribute definition.
     */
    private Object getAttributeValue(AttributeDefinition attrDef, AuthorizationRequest request) {
        return switch (attrDef.getCategory()) {
            case SUBJECT -> request.getSubjectAttributes().get(attrDef.getName());
            case RESOURCE -> request.getResourceAttributes().get(attrDef.getName());
            case ACTION -> request.getAction();
            case ENVIRONMENT -> getEnvironmentAttribute(attrDef, request);
        };
    }

    /**
     * Gets environment attribute (time, IP, etc.).
     */
    private Object getEnvironmentAttribute(AttributeDefinition attrDef, AuthorizationRequest request) {
        Object envValue = request.getEnvironmentAttributes().get(attrDef.getName());
        if (envValue != null) {
            return envValue;
        }

        // Built-in environment attributes
        return switch (attrDef.getName()) {
            case "current_time" -> LocalDateTime.now(ZoneOffset.UTC);
            case "current_date" -> LocalDateTime.now(ZoneOffset.UTC).toLocalDate();
            case "current_hour" -> LocalDateTime.now(ZoneOffset.UTC).getHour();
            case "day_of_week" -> LocalDateTime.now(ZoneOffset.UTC).getDayOfWeek().getValue();
            default -> null;
        };
    }

    /**
     * Evaluates an operator against actual and expected values.
     */
    private boolean evaluateOperator(
            ConditionOperator operator,
            Object actualValue,
            String expectedValue,
            String expectedValue2,
            AttributeDataType dataType) {

        String actualStr = String.valueOf(actualValue);

        return switch (operator) {
            case EQUALS -> actualStr.equals(expectedValue);
            case NOT_EQUALS -> !actualStr.equals(expectedValue);
            case CONTAINS -> actualStr.contains(expectedValue);
            case NOT_CONTAINS -> !actualStr.contains(expectedValue);
            case STARTS_WITH -> actualStr.startsWith(expectedValue);
            case ENDS_WITH -> actualStr.endsWith(expectedValue);
            case MATCHES_REGEX -> matchesRegex(actualStr, expectedValue);
            case IN -> isIn(actualStr, expectedValue);
            case NOT_IN -> !isIn(actualStr, expectedValue);
            case IS_NULL -> actualValue == null;
            case IS_NOT_NULL -> actualValue != null;
            case GREATER_THAN -> compareNumbers(actualStr, expectedValue) > 0;
            case GREATER_THAN_OR_EQUALS -> compareNumbers(actualStr, expectedValue) >= 0;
            case LESS_THAN -> compareNumbers(actualStr, expectedValue) < 0;
            case LESS_THAN_OR_EQUALS -> compareNumbers(actualStr, expectedValue) <= 0;
            case BETWEEN -> isBetween(actualStr, expectedValue, expectedValue2, dataType);
            default -> false;
        };
    }

    private boolean matchesRegex(String value, String regex) {
        Pattern pattern = regexCache.computeIfAbsent(regex, Pattern::compile);
        return pattern.matcher(value).matches();
    }

    private boolean isIn(String value, String listJson) {
        // Expecting comma-separated values or JSON array
        if (listJson.startsWith("[")) {
            listJson = listJson.substring(1, listJson.length() - 1);
        }
        String[] items = listJson.split(",");
        for (String item : items) {
            if (item.trim().replace("\"", "").equals(value)) {
                return true;
            }
        }
        return false;
    }

    private int compareNumbers(String actual, String expected) {
        try {
            BigDecimal actualNum = new BigDecimal(actual);
            BigDecimal expectedNum = new BigDecimal(expected);
            return actualNum.compareTo(expectedNum);
        } catch (NumberFormatException e) {
            return actual.compareTo(expected);
        }
    }

    private boolean isBetween(String value, String min, String max, AttributeDataType dataType) {
        return compareNumbers(value, min) >= 0 && compareNumbers(value, max) <= 0;
    }

    /**
     * Applies combining algorithm to get final decision.
     */
    private Decision applyCombiningAlgorithm(List<PolicyEvaluationResult> results, CombiningAlgorithm algorithm) {
        return switch (algorithm) {
            case DENY_OVERRIDES -> {
                for (PolicyEvaluationResult result : results) {
                    if (result.decision == Decision.DENY)
                        yield Decision.DENY;
                }
                for (PolicyEvaluationResult result : results) {
                    if (result.decision == Decision.PERMIT)
                        yield Decision.PERMIT;
                }
                yield Decision.NOT_APPLICABLE;
            }
            case PERMIT_OVERRIDES -> {
                for (PolicyEvaluationResult result : results) {
                    if (result.decision == Decision.PERMIT)
                        yield Decision.PERMIT;
                }
                for (PolicyEvaluationResult result : results) {
                    if (result.decision == Decision.DENY)
                        yield Decision.DENY;
                }
                yield Decision.NOT_APPLICABLE;
            }
            case FIRST_APPLICABLE -> results.stream()
                    .filter(r -> r.decision != Decision.NOT_APPLICABLE)
                    .map(r -> r.decision)
                    .findFirst()
                    .orElse(Decision.NOT_APPLICABLE);
            default -> Decision.NOT_APPLICABLE;
        };
    }

    private record PolicyEvaluationResult(String policyName, Decision decision, String reason) {
    }

    private AuthorizationResponse buildResponse(Decision decision, String reason, long startTimeNanos,
            String determinedBy) {
        double evaluationTimeMs = (System.nanoTime() - startTimeNanos) / 1_000_000.0;

        return AuthorizationResponse.builder()
                .decision(decision)
                .mode(AuthorizationMode.ABAC)
                .reason(reason)
                .determinedBy(determinedBy)
                .evaluationTimeMs(evaluationTimeMs)
                .build();
    }
}
