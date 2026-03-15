package com.pss.authorization.domain.service;

import com.pss.authorization.domain.dto.ContextRoutingBitmap;
import com.pss.authorization.domain.dto.PolicyApplicabilityBitmap;
import com.pss.authorization.domain.model.abac.Policy;
import com.pss.authorization.domain.model.hybrid.AuthorizationContext;
import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import com.pss.authorization.domain.model.hybrid.CombiningStrategy;
import com.pss.authorization.persistence.repository.AuthorizationContextRepository;
import com.pss.authorization.persistence.repository.PolicyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BitmapBuilderServiceTest {

    private static final String TENANT = "test-tenant";

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private AuthorizationContextRepository contextRepository;

    @InjectMocks
    private BitmapBuilderService bitmapBuilderService;

    @BeforeEach
    void setUp() {
    }

    @Test
    void buildPolicyBitmap_shouldMapExactAndWildcardTargets() {
        // Arrange
        Policy exactPolicy = Policy.builder()
                .targetResource("flight")
                .targetAction("READ")
                .bitIndex(0)
                .build();
        exactPolicy.setTenantId(TENANT);

        Policy prefixPolicy = Policy.builder()
                .targetResource("flight:*")
                .targetAction("WRITE")
                .bitIndex(1)
                .build();
        prefixPolicy.setTenantId(TENANT);

        Policy globalPolicy = Policy.builder()
                .targetResource("*")
                .targetAction("ALL")
                .bitIndex(2)
                .build();
        globalPolicy.setTenantId(TENANT);

        when(policyRepository.findActivePoliciesWithRules(TENANT))
                .thenReturn(List.of(exactPolicy, prefixPolicy, globalPolicy));

        // Act
        PolicyApplicabilityBitmap bitmap = bitmapBuilderService.buildPolicyBitmap(TENANT);

        // Assert
        assertThat(bitmap.tenantId()).isEqualTo(TENANT);
        assertThat(bitmap.policyIndex()).hasSize(3);

        List<Policy> exactMatches = bitmap.getApplicablePolicies("flight", "READ");
        assertThat(exactMatches).containsExactly(exactPolicy, globalPolicy);

        List<Policy> prefixMatches = bitmap.getApplicablePolicies("flight:domestic", "WRITE");
        assertThat(prefixMatches).containsExactly(prefixPolicy, globalPolicy);

        List<Policy> globalMatches = bitmap.getApplicablePolicies("unknown", "READ");
        assertThat(globalMatches).containsExactly(globalPolicy);
    }

    @Test
    void buildContextRoutingBitmap_shouldMapExactAndPrefixPatterns() {
        // Arrange
        AuthorizationContext exactContext = AuthorizationContext.builder()
                .name("Exact Flight Context")
                .resourcePattern("flight")
                .combiningStrategy(CombiningStrategy.RBAC_FIRST)
                .mode(AuthorizationMode.HYBRID)
                .priority(1)
                .build();
        exactContext.setTenantId(TENANT);

        AuthorizationContext prefixContext = AuthorizationContext.builder()
                .name("Prefix Flight Context")
                .resourcePattern("flight:*")
                .combiningStrategy(CombiningStrategy.ABAC_FIRST)
                .mode(AuthorizationMode.RBAC) // just to test it's mapped
                .priority(1)
                .build();
        prefixContext.setTenantId(TENANT);

        AuthorizationContext globalContext = AuthorizationContext.builder()
                .name("Global Context")
                .resourcePattern("*")
                .combiningStrategy(CombiningStrategy.OR)
                .mode(AuthorizationMode.HYBRID)
                .priority(10)
                .build();
        globalContext.setTenantId(TENANT);

        when(contextRepository.findActiveContextsWithRules(TENANT))
                .thenReturn(List.of(exactContext, prefixContext, globalContext));

        // Act
        ContextRoutingBitmap routingBitmap = bitmapBuilderService.buildContextRoutingBitmap(TENANT);

        // Assert
        assertThat(routingBitmap.tenantId()).isEqualTo(TENANT);

        // Test exact
        ContextRoutingBitmap.ContextConfig exactConfig = routingBitmap.resolve("flight");
        assertThat(exactConfig.strategy()).isEqualTo(CombiningStrategy.RBAC_FIRST);
        assertThat(exactConfig.mode()).isEqualTo(AuthorizationMode.HYBRID);

        // Test prefix
        ContextRoutingBitmap.ContextConfig prefixConfig = routingBitmap.resolve("flight:domestic");
        assertThat(prefixConfig.strategy()).isEqualTo(CombiningStrategy.ABAC_FIRST);
        assertThat(prefixConfig.mode()).isEqualTo(AuthorizationMode.RBAC);

        // Test global
        ContextRoutingBitmap.ContextConfig globalConfig = routingBitmap.resolve("unknown");
        assertThat(globalConfig.strategy()).isEqualTo(CombiningStrategy.OR);
        assertThat(globalConfig.mode()).isEqualTo(AuthorizationMode.HYBRID);
    }
}
