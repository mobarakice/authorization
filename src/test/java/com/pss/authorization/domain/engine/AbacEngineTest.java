package com.pss.authorization.domain.engine;

import com.pss.authorization.cache.TwoLevelCacheManager;
import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.dto.AuthorizationResponse.Decision;
import com.pss.authorization.domain.model.abac.*;
import com.pss.authorization.persistence.repository.PolicyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AbacEngineTest {

    static final String TENANT = "pss-test";
    static final String RESOURCE = "price";
    static final String ACTION = "BLOCK";

    @Mock TwoLevelCacheManager cacheManager;
    @Mock PolicyRepository policyRepository;

    @InjectMocks AbacEngine abacEngine;

    private AuthorizationRequest request;

    @BeforeEach
    void setUp() {
        // Cache always misses — delegate to DB mock
        when(cacheManager.getPoliciesByTarget(anyString(), anyString(), anyString()))
                .thenReturn(Optional.empty());
        doNothing().when(cacheManager).putPoliciesByTarget(anyString(), anyString(), anyString(), any());

        request = AuthorizationRequest.builder()
                .tenantId(TENANT)
                .externalSubjectId("shamim")
                .resource(RESOURCE)
                .action(ACTION)
                .subjectAttributes(new HashMap<>())
                .build();
    }

    // --- Helper builders ---

    private Policy buildPermitPolicy(String attrName, ConditionOperator operator, String expectedValue) {
        AttributeDefinition attrDef = AttributeDefinition.builder()
                .id(UUID.randomUUID())
                .name(attrName)
                .category(AttributeCategory.SUBJECT)
                .dataType(AttributeDataType.STRING)
                .source("DATABASE")
                .build();

        RuleCondition condition = RuleCondition.builder()
                .id(UUID.randomUUID())
                .attribute(attrDef)
                .operator(operator)
                .expectedValue(expectedValue)
                .negate(false)
                .orderIndex(0)
                .build();

        PolicyRule rule = PolicyRule.builder()
                .id(UUID.randomUUID())
                .name("test-rule")
                .conditionLogic("AND")
                .active(true)
                .conditions(new LinkedHashSet<>(List.of(condition)))
                .orderIndex(0)
                .build();

        return Policy.builder()
                .id(UUID.randomUUID())
                .name("test-policy")
                .targetResource(RESOURCE)
                .targetAction(ACTION)
                .effect(PolicyEffect.PERMIT)
                .priority(10)
                .combiningAlgorithm(CombiningAlgorithm.DENY_OVERRIDES)
                .active(true)
                .rules(new LinkedHashSet<>(List.of(rule)))
                .build();
    }

    private Policy buildDenyPolicy(String attrName, ConditionOperator operator, String expectedValue) {
        Policy permit = buildPermitPolicy(attrName, operator, expectedValue);
        permit.setEffect(PolicyEffect.DENY);
        return permit;
    }

    // --- canHandle ---

    @Test
    void canHandle_withAllRequiredFields_returnsTrue() {
        assertThat(abacEngine.canHandle(request)).isTrue();
    }

    @Test
    void canHandle_nullResource_returnsFalse() {
        var req = AuthorizationRequest.builder().tenantId(TENANT).action(ACTION).build();
        assertThat(abacEngine.canHandle(req)).isFalse();
    }

    @Test
    void canHandle_nullAction_returnsFalse() {
        var req = AuthorizationRequest.builder().tenantId(TENANT).resource(RESOURCE).build();
        assertThat(abacEngine.canHandle(req)).isFalse();
    }

    // --- evaluate: no policies ---

    @Test
    void evaluate_noPolicies_returnsNotApplicable() {
        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of());

        AuthorizationResponse response = abacEngine.evaluate(request);

        assertThat(response.getDecision()).isEqualTo(Decision.NOT_APPLICABLE);
        assertThat(response.getReason()).containsIgnoringCase("No applicable ABAC policies");
    }

    // --- evaluate: CONTAINS operator ---

    @Test
    void evaluate_containsMatch_returnsPermit() {
        request.getSubjectAttributes().put("extra_permissions", "price:BLOCK");

        Policy policy = buildPermitPolicy("extra_permissions", ConditionOperator.CONTAINS, "price:BLOCK");
        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of(policy));

        AuthorizationResponse response = abacEngine.evaluate(request);

        assertThat(response.getDecision()).isEqualTo(Decision.PERMIT);
    }

    @Test
    void evaluate_containsNoMatch_returnsNotApplicable() {
        // subjectAttributes is empty — no extra_permissions
        Policy policy = buildPermitPolicy("extra_permissions", ConditionOperator.CONTAINS, "price:BLOCK");
        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of(policy));

        AuthorizationResponse response = abacEngine.evaluate(request);

        // attribute value is null → condition false → rules not matched → NOT_APPLICABLE
        assertThat(response.getDecision()).isEqualTo(Decision.NOT_APPLICABLE);
    }

    @Test
    void evaluate_containsWrongValue_returnsNotApplicable() {
        request.getSubjectAttributes().put("extra_permissions", "pnl:BLOCK");

        Policy policy = buildPermitPolicy("extra_permissions", ConditionOperator.CONTAINS, "price:BLOCK");
        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of(policy));

        AuthorizationResponse response = abacEngine.evaluate(request);

        assertThat(response.getDecision()).isEqualTo(Decision.NOT_APPLICABLE);
    }

    // --- evaluate: EQUALS operator ---

    @Test
    void evaluate_equalsMatch_returnsPermit() {
        request.getSubjectAttributes().put("department", "FINANCE");

        Policy policy = buildPermitPolicy("department", ConditionOperator.EQUALS, "FINANCE");
        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of(policy));

        assertThat(abacEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    @Test
    void evaluate_equalsNoMatch_returnsNotApplicable() {
        request.getSubjectAttributes().put("department", "SALES");

        Policy policy = buildPermitPolicy("department", ConditionOperator.EQUALS, "FINANCE");
        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of(policy));

        assertThat(abacEngine.evaluate(request).getDecision()).isEqualTo(Decision.NOT_APPLICABLE);
    }

    // --- evaluate: DENY_OVERRIDES combining algorithm ---

    @Test
    void evaluate_denyOverrides_denyWinsOverPermit() {
        request.getSubjectAttributes().put("extra_permissions", "price:BLOCK");

        Policy permitPolicy = buildPermitPolicy("extra_permissions", ConditionOperator.CONTAINS, "price:BLOCK");
        Policy denyPolicy = buildDenyPolicy("extra_permissions", ConditionOperator.CONTAINS, "price:BLOCK");
        denyPolicy.setName("deny-policy");

        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of(permitPolicy, denyPolicy));

        assertThat(abacEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
    }

    @Test
    void evaluate_denyPolicy_matchedCondition_returnsDeny() {
        request.getSubjectAttributes().put("blocked", "true");

        Policy denyPolicy = buildDenyPolicy("blocked", ConditionOperator.EQUALS, "true");
        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of(denyPolicy));

        assertThat(abacEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
    }

    // --- evaluate: negated condition ---

    @Test
    void evaluate_negatedConditionMatchBecomesNonMatch_returnsNotApplicable() {
        request.getSubjectAttributes().put("extra_permissions", "price:BLOCK");

        AttributeDefinition attrDef = AttributeDefinition.builder()
                .id(UUID.randomUUID())
                .name("extra_permissions")
                .category(AttributeCategory.SUBJECT)
                .dataType(AttributeDataType.STRING)
                .source("DATABASE")
                .build();

        RuleCondition negatedCond = RuleCondition.builder()
                .id(UUID.randomUUID())
                .attribute(attrDef)
                .operator(ConditionOperator.CONTAINS)
                .expectedValue("price:BLOCK")
                .negate(true)   // negated: match becomes false
                .orderIndex(0)
                .build();

        PolicyRule rule = PolicyRule.builder()
                .id(UUID.randomUUID())
                .name("negated-rule")
                .conditionLogic("AND")
                .active(true)
                .conditions(new LinkedHashSet<>(List.of(negatedCond)))
                .orderIndex(0)
                .build();

        Policy policy = Policy.builder()
                .id(UUID.randomUUID())
                .name("negated-policy")
                .targetResource(RESOURCE)
                .targetAction(ACTION)
                .effect(PolicyEffect.PERMIT)
                .priority(10)
                .combiningAlgorithm(CombiningAlgorithm.DENY_OVERRIDES)
                .active(true)
                .rules(new LinkedHashSet<>(List.of(rule)))
                .build();

        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of(policy));

        assertThat(abacEngine.evaluate(request).getDecision()).isEqualTo(Decision.NOT_APPLICABLE);
    }

    // --- evaluate: OR condition logic ---

    @Test
    void evaluate_orConditionLogic_oneMatchPermits() {
        request.getSubjectAttributes().put("extra_permissions", "price:BLOCK");

        AttributeDefinition attrDef = AttributeDefinition.builder()
                .id(UUID.randomUUID())
                .name("extra_permissions")
                .category(AttributeCategory.SUBJECT)
                .dataType(AttributeDataType.STRING)
                .source("DATABASE")
                .build();

        // First condition won't match, second will
        RuleCondition cond1 = RuleCondition.builder()
                .id(UUID.randomUUID()).attribute(attrDef).operator(ConditionOperator.EQUALS)
                .expectedValue("wrong-value").negate(false).orderIndex(0).build();
        RuleCondition cond2 = RuleCondition.builder()
                .id(UUID.randomUUID()).attribute(attrDef).operator(ConditionOperator.CONTAINS)
                .expectedValue("price:BLOCK").negate(false).orderIndex(1).build();

        PolicyRule rule = PolicyRule.builder()
                .id(UUID.randomUUID())
                .name("or-rule")
                .conditionLogic("OR")  // OR logic
                .active(true)
                .conditions(new LinkedHashSet<>(List.of(cond1, cond2)))
                .orderIndex(0)
                .build();

        Policy policy = Policy.builder()
                .id(UUID.randomUUID())
                .name("or-policy")
                .targetResource(RESOURCE).targetAction(ACTION)
                .effect(PolicyEffect.PERMIT)
                .priority(10).combiningAlgorithm(CombiningAlgorithm.DENY_OVERRIDES)
                .active(true)
                .rules(new LinkedHashSet<>(List.of(rule)))
                .build();

        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of(policy));

        assertThat(abacEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    // --- evaluate: inactive rule skipped ---

    @Test
    void evaluate_inactiveRule_skipped_policyStillApplies() {
        // AbacEngine initialises allRulesMatch=true; skipping ALL rules leaves it true
        // so the policy effect fires regardless of conditions.
        request.getSubjectAttributes().put("extra_permissions", "price:BLOCK");

        Policy policy = buildPermitPolicy("extra_permissions", ConditionOperator.CONTAINS, "price:BLOCK");
        policy.getRules().forEach(r -> r.setActive(false));

        when(policyRepository.findApplicablePolicies(TENANT, RESOURCE, ACTION))
                .thenReturn(List.of(policy));

        // Behaviour: no active rule → allRulesMatch stays true → effect (PERMIT) is applied
        assertThat(abacEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    // --- getEngineType ---

    @Test
    void getEngineType_returnsABAC() {
        assertThat(abacEngine.getEngineType()).isEqualTo("ABAC");
    }
}
