package com.pss.authorization.domain.engine;

import com.pss.authorization.cache.TwoLevelCacheManager;
import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.dto.AuthorizationResponse.Decision;
import com.pss.authorization.domain.dto.ContextRoutingBitmap;
import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import com.pss.authorization.domain.model.hybrid.CombiningStrategy;
import com.pss.authorization.domain.service.BitmapBuilderService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class HybridEngineTest {

    static final String TENANT = "pss-test";
    static final String RESOURCE = "price";
    static final String ACTION = "BLOCK";

    @Mock
    RbacEngine rbacEngine;
    @Mock
    AbacEngine abacEngine;
    @Mock
    TwoLevelCacheManager cacheManager;
    @Mock
    BitmapBuilderService bitmapBuilderService;

    @InjectMocks
    HybridEngine hybridEngine;

    private AuthorizationRequest request;

    @BeforeEach
    void setUp() {
        request = AuthorizationRequest.builder()
                .tenantId(TENANT)
                .externalSubjectId("shamim")
                .resource(RESOURCE)
                .action(ACTION)
                .build();
    }

    // --- Context routing helpers ---

    /**
     * Stubs the ContextRoutingBitmap to return the given strategy for any resource.
     */
    private void withStrategy(CombiningStrategy strategy) {
        ContextRoutingBitmap routing = ContextRoutingBitmap.builder()
                .tenantId(TENANT)
                .defaultConfig(new ContextRoutingBitmap.ContextConfig(strategy, AuthorizationMode.HYBRID))
                .version(1L)
                .computedAt(System.currentTimeMillis())
                .build();
        when(cacheManager.getContextRoutingBitmap(TENANT))
                .thenReturn(Optional.of(routing));
    }

    private AuthorizationResponse permit(String reason) {
        return AuthorizationResponse.builder()
                .decision(Decision.PERMIT).reason(reason).evaluationTimeMs(0.5).build();
    }

    private AuthorizationResponse deny(String reason) {
        return AuthorizationResponse.builder()
                .decision(Decision.DENY).reason(reason).evaluationTimeMs(0.5).build();
    }

    private AuthorizationResponse notApplicable() {
        return AuthorizationResponse.builder()
                .decision(Decision.NOT_APPLICABLE).reason("no match").evaluationTimeMs(0.5).build();
    }

    // --- RBAC_FIRST strategy ---

    @Test
    void rbacFirst_rbacDeny_shortCircuits_neverCallsAbac() {
        withStrategy(CombiningStrategy.RBAC_FIRST);
        when(rbacEngine.evaluate(request)).thenReturn(deny("no role"));

        AuthorizationResponse response = hybridEngine.evaluate(request);

        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
        verifyNoInteractions(abacEngine);
    }

    @Test
    void rbacFirst_rbacPermit_abacPermit_returnsPermit() {
        withStrategy(CombiningStrategy.RBAC_FIRST);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role grants"));
        when(abacEngine.evaluate(request)).thenReturn(permit("abac ok"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    @Test
    void rbacFirst_rbacPermit_abacDeny_returnsDeny() {
        withStrategy(CombiningStrategy.RBAC_FIRST);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role grants"));
        when(abacEngine.evaluate(request)).thenReturn(deny("abac blocks"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
    }

    @Test
    void rbacFirst_rbacNotApplicable_returnsNotApplicable() {
        withStrategy(CombiningStrategy.RBAC_FIRST);
        when(rbacEngine.evaluate(request)).thenReturn(notApplicable());

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.NOT_APPLICABLE);
        verifyNoInteractions(abacEngine);
    }

    // --- ABAC_FIRST strategy ---

    @Test
    void abacFirst_abacDeny_shortCircuits_neverCallsRbac() {
        withStrategy(CombiningStrategy.ABAC_FIRST);
        when(abacEngine.evaluate(request)).thenReturn(deny("abac blocks"));

        AuthorizationResponse response = hybridEngine.evaluate(request);

        assertThat(response.getDecision()).isEqualTo(Decision.DENY);
        verifyNoInteractions(rbacEngine);
    }

    @Test
    void abacFirst_abacPermit_rbacPermit_returnsPermit() {
        withStrategy(CombiningStrategy.ABAC_FIRST);
        when(abacEngine.evaluate(request)).thenReturn(permit("abac ok"));
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    @Test
    void abacFirst_abacPermit_rbacDeny_returnsDeny() {
        withStrategy(CombiningStrategy.ABAC_FIRST);
        when(abacEngine.evaluate(request)).thenReturn(permit("abac ok"));
        when(rbacEngine.evaluate(request)).thenReturn(deny("no role"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
    }

    @Test
    void abacFirst_abacNotApplicable_fallsBackToRbac() {
        withStrategy(CombiningStrategy.ABAC_FIRST);
        when(abacEngine.evaluate(request)).thenReturn(notApplicable());
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
        verify(rbacEngine).evaluate(request);
    }

    // --- AND strategy ---

    @Test
    void and_bothPermit_returnsPermit() {
        withStrategy(CombiningStrategy.AND);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));
        when(abacEngine.evaluate(request)).thenReturn(permit("abac ok"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    @Test
    void and_rbacDeny_returnsDeny() {
        withStrategy(CombiningStrategy.AND);
        when(rbacEngine.evaluate(request)).thenReturn(deny("no role"));
        when(abacEngine.evaluate(request)).thenReturn(permit("abac ok"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
    }

    @Test
    void and_abacDeny_returnsDeny() {
        withStrategy(CombiningStrategy.AND);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));
        when(abacEngine.evaluate(request)).thenReturn(deny("abac blocks"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
    }

    @Test
    void and_rbacPermit_abacNotApplicable_returnsPermit() {
        // ABAC has no opinion → RBAC alone is sufficient
        withStrategy(CombiningStrategy.AND);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));
        when(abacEngine.evaluate(request)).thenReturn(notApplicable());

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    @Test
    void and_abacPermit_rbacNotApplicable_returnsDeny() {
        // RBAC not applicable means no role grants it → must DENY
        withStrategy(CombiningStrategy.AND);
        when(rbacEngine.evaluate(request)).thenReturn(notApplicable());
        when(abacEngine.evaluate(request)).thenReturn(permit("abac ok"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
    }

    // --- OR strategy ---

    @Test
    void or_rbacPermit_shortCircuits_neverCallsAbac() {
        withStrategy(CombiningStrategy.OR);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
        verifyNoInteractions(abacEngine);
    }

    @Test
    void or_rbacNotPermit_abacPermit_returnsPermit() {
        withStrategy(CombiningStrategy.OR);
        when(rbacEngine.evaluate(request)).thenReturn(deny("no role"));
        when(abacEngine.evaluate(request)).thenReturn(permit("extra perm"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    @Test
    void or_bothDeny_returnsDeny() {
        withStrategy(CombiningStrategy.OR);
        when(rbacEngine.evaluate(request)).thenReturn(deny("no role"));
        when(abacEngine.evaluate(request)).thenReturn(deny("abac blocks"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
    }

    @Test
    void or_bothNotApplicable_returnsNotApplicable() {
        withStrategy(CombiningStrategy.OR);
        when(rbacEngine.evaluate(request)).thenReturn(notApplicable());
        when(abacEngine.evaluate(request)).thenReturn(notApplicable());

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.NOT_APPLICABLE);
    }

    // --- RBAC_REQUIRED_ABAC_CONSTRAINS strategy ---

    @Test
    void rbacRequiredAbacConstrains_rbacDeny_returnsDeny() {
        withStrategy(CombiningStrategy.RBAC_REQUIRED_ABAC_CONSTRAINS);
        when(rbacEngine.evaluate(request)).thenReturn(deny("no role"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
        verifyNoInteractions(abacEngine);
    }

    @Test
    void rbacRequiredAbacConstrains_rbacPermit_abacPermit_returnsPermit() {
        withStrategy(CombiningStrategy.RBAC_REQUIRED_ABAC_CONSTRAINS);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));
        when(abacEngine.evaluate(request)).thenReturn(permit("abac ok"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    @Test
    void rbacRequiredAbacConstrains_rbacPermit_abacDeny_returnsDeny() {
        withStrategy(CombiningStrategy.RBAC_REQUIRED_ABAC_CONSTRAINS);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));
        when(abacEngine.evaluate(request)).thenReturn(deny("abac constrains"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
    }

    @Test
    void rbacRequiredAbacConstrains_rbacPermit_abacNotApplicable_returnsPermit() {
        withStrategy(CombiningStrategy.RBAC_REQUIRED_ABAC_CONSTRAINS);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));
        when(abacEngine.evaluate(request)).thenReturn(notApplicable());

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    // --- ABAC_PRIMARY_RBAC_FALLBACK strategy ---

    @Test
    void abacPrimaryRbacFallback_abacPermit_returnsPermit_noRbacCall() {
        withStrategy(CombiningStrategy.ABAC_PRIMARY_RBAC_FALLBACK);
        when(abacEngine.evaluate(request)).thenReturn(permit("extra perm"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
        verifyNoInteractions(rbacEngine);
    }

    @Test
    void abacPrimaryRbacFallback_abacDeny_returnsDeny_noRbacCall() {
        withStrategy(CombiningStrategy.ABAC_PRIMARY_RBAC_FALLBACK);
        when(abacEngine.evaluate(request)).thenReturn(deny("blocked"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.DENY);
        verifyNoInteractions(rbacEngine);
    }

    @Test
    void abacPrimaryRbacFallback_abacNotApplicable_fallsBackToRbac() {
        withStrategy(CombiningStrategy.ABAC_PRIMARY_RBAC_FALLBACK);
        when(abacEngine.evaluate(request)).thenReturn(notApplicable());
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));

        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
        verify(rbacEngine).evaluate(request);
    }

    // --- Strategy from bitmap (cache miss path) ---

    @Test
    void getStrategy_cacheMiss_buildsBitmapFromDB_cachesIt() {
        when(cacheManager.getContextRoutingBitmap(TENANT)).thenReturn(Optional.empty());
        ContextRoutingBitmap routing = ContextRoutingBitmap.builder()
                .tenantId(TENANT)
                .defaultConfig(new ContextRoutingBitmap.ContextConfig(CombiningStrategy.OR, AuthorizationMode.HYBRID))
                .version(1L)
                .computedAt(System.currentTimeMillis())
                .build();
        when(bitmapBuilderService.buildContextRoutingBitmap(TENANT)).thenReturn(routing);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));

        hybridEngine.evaluate(request);

        // Verify bitmap is cached after DB build
        verify(cacheManager).putContextRoutingBitmap(eq(TENANT), eq(routing));
    }

    @Test
    void getStrategy_cacheMiss_buildsBitmapFromDB_usesStrategy() {
        when(cacheManager.getContextRoutingBitmap(TENANT)).thenReturn(Optional.empty());
        ContextRoutingBitmap routing = ContextRoutingBitmap.builder()
                .tenantId(TENANT)
                .defaultConfig(new ContextRoutingBitmap.ContextConfig(CombiningStrategy.OR, AuthorizationMode.HYBRID))
                .version(1L)
                .computedAt(System.currentTimeMillis())
                .build();
        when(bitmapBuilderService.buildContextRoutingBitmap(TENANT)).thenReturn(routing);
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));

        // OR strategy: RBAC permits → short-circuit, no ABAC call
        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
        verifyNoInteractions(abacEngine);
    }

    @Test
    void getStrategy_noContext_defaultsToAnd() {
        // Empty routing bitmap → defaults to AND
        ContextRoutingBitmap routing = ContextRoutingBitmap.builder()
                .tenantId(TENANT)
                .version(1L)
                .computedAt(System.currentTimeMillis())
                .build();
        when(cacheManager.getContextRoutingBitmap(TENANT)).thenReturn(Optional.of(routing));
        when(rbacEngine.evaluate(request)).thenReturn(permit("role ok"));
        when(abacEngine.evaluate(request)).thenReturn(permit("abac ok"));

        // AND (default): both called, both permit → PERMIT
        assertThat(hybridEngine.evaluate(request).getDecision()).isEqualTo(Decision.PERMIT);
    }

    // --- getEngineType ---

    @Test
    void getEngineType_returnsHYBRID() {
        assertThat(hybridEngine.getEngineType()).isEqualTo("HYBRID");
    }

    // --- canHandle ---

    @Test
    void canHandle_whenBothEnginesCanHandle_returnsTrue() {
        when(rbacEngine.canHandle(request)).thenReturn(true);
        when(abacEngine.canHandle(request)).thenReturn(true);
        assertThat(hybridEngine.canHandle(request)).isTrue();
    }

    @Test
    void canHandle_rbacCannotHandle_returnsFalse() {
        when(rbacEngine.canHandle(request)).thenReturn(false);
        assertThat(hybridEngine.canHandle(request)).isFalse();
    }
}
