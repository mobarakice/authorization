package com.pss.authorization.service;

import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.dto.AuthorizationResponse.Decision;
import com.pss.authorization.domain.model.rbac.Subject;
import com.pss.authorization.domain.model.rbac.SubjectAttribute;
import com.pss.authorization.domain.xacml.PolicyDecisionPoint;
import com.pss.authorization.persistence.repository.SubjectRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationServiceTest {

    static final String TENANT = "pss-test";
    static final String EXT_ID = "shamim";

    @Mock PolicyDecisionPoint pdp;
    @Mock SubjectRepository subjectRepository;

    @InjectMocks AuthorizationService authorizationService;

    private AuthorizationRequest request;
    private AuthorizationResponse permitResponse;

    @BeforeEach
    void setUp() {
        request = AuthorizationRequest.builder()
                .tenantId(TENANT)
                .externalSubjectId(EXT_ID)
                .resource("price")
                .action("BLOCK")
                .subjectAttributes(new HashMap<>())
                .build();

        permitResponse = AuthorizationResponse.builder()
                .decision(Decision.PERMIT)
                .reason("granted")
                .build();
    }

    // --- Helper ---

    private SubjectAttribute attribute(String name, String value) {
        return SubjectAttribute.builder()
                .id(UUID.randomUUID())
                .attributeName(name)
                .attributeValue(value)
                .valueType("STRING")
                .build();
    }

    // --- authorize: attribute enrichment ---

    @Test
    void authorize_enrichesSubjectAttributesFromDB() {
        Subject subject = Subject.builder()
                .id(UUID.randomUUID())
                .externalId(EXT_ID)
                .attributes(Set.of(attribute("extra_permissions", "price:BLOCK")))
                .build();
        when(subjectRepository.findByExternalIdWithAttributes(TENANT, EXT_ID))
                .thenReturn(Optional.of(subject));
        when(pdp.evaluate(any())).thenReturn(permitResponse);

        authorizationService.authorize(request);

        // Capture what PDP received
        ArgumentCaptor<AuthorizationRequest> captor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        verify(pdp).evaluate(captor.capture());
        assertThat(captor.getValue().getSubjectAttributes())
                .containsEntry("extra_permissions", "price:BLOCK");
    }

    @Test
    void authorize_subjectHasNoAttributes_pdpCalledWithEmptyAttributes() {
        Subject subject = Subject.builder()
                .id(UUID.randomUUID())
                .externalId(EXT_ID)
                .attributes(new HashSet<>())
                .build();
        when(subjectRepository.findByExternalIdWithAttributes(TENANT, EXT_ID))
                .thenReturn(Optional.of(subject));
        when(pdp.evaluate(any())).thenReturn(permitResponse);

        authorizationService.authorize(request);

        ArgumentCaptor<AuthorizationRequest> captor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        verify(pdp).evaluate(captor.capture());
        assertThat(captor.getValue().getSubjectAttributes()).isEmpty();
    }

    @Test
    void authorize_subjectNotFound_pdpCalledWithEmptyAttributes() {
        when(subjectRepository.findByExternalIdWithAttributes(TENANT, EXT_ID))
                .thenReturn(Optional.empty());
        when(pdp.evaluate(any())).thenReturn(permitResponse);

        authorizationService.authorize(request);

        ArgumentCaptor<AuthorizationRequest> captor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        verify(pdp).evaluate(captor.capture());
        assertThat(captor.getValue().getSubjectAttributes()).isEmpty();
    }

    // --- authorize: null guards ---

    @Test
    void authorize_nullTenantId_skipsEnrichment() {
        request.setTenantId(null);
        when(pdp.evaluate(any())).thenReturn(permitResponse);

        authorizationService.authorize(request);

        verifyNoInteractions(subjectRepository);
        verify(pdp).evaluate(request);
    }

    @Test
    void authorize_nullExternalSubjectId_skipsEnrichment() {
        request.setExternalSubjectId(null);
        when(pdp.evaluate(any())).thenReturn(permitResponse);

        authorizationService.authorize(request);

        verifyNoInteractions(subjectRepository);
        verify(pdp).evaluate(request);
    }

    // --- authorize: putIfAbsent semantics ---

    @Test
    void authorize_callerProvidedAttributeNotOverwrittenByDB() {
        // Caller provides extra_permissions = "caller-value"
        request.getSubjectAttributes().put("extra_permissions", "caller-value");

        Subject subject = Subject.builder()
                .id(UUID.randomUUID())
                .externalId(EXT_ID)
                .attributes(Set.of(attribute("extra_permissions", "db-value")))
                .build();
        when(subjectRepository.findByExternalIdWithAttributes(TENANT, EXT_ID))
                .thenReturn(Optional.of(subject));
        when(pdp.evaluate(any())).thenReturn(permitResponse);

        authorizationService.authorize(request);

        ArgumentCaptor<AuthorizationRequest> captor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        verify(pdp).evaluate(captor.capture());
        // putIfAbsent: caller value must win
        assertThat(captor.getValue().getSubjectAttributes())
                .containsEntry("extra_permissions", "caller-value");
    }

    @Test
    void authorize_multipleAttributesMerged() {
        Subject subject = Subject.builder()
                .id(UUID.randomUUID())
                .externalId(EXT_ID)
                .attributes(Set.of(
                        attribute("extra_permissions", "price:BLOCK"),
                        attribute("department", "FINANCE")
                ))
                .build();
        when(subjectRepository.findByExternalIdWithAttributes(TENANT, EXT_ID))
                .thenReturn(Optional.of(subject));
        when(pdp.evaluate(any())).thenReturn(permitResponse);

        authorizationService.authorize(request);

        ArgumentCaptor<AuthorizationRequest> captor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        verify(pdp).evaluate(captor.capture());
        assertThat(captor.getValue().getSubjectAttributes())
                .containsEntry("extra_permissions", "price:BLOCK")
                .containsEntry("department", "FINANCE");
    }

    // --- authorize: expired attribute ---

    @Test
    void authorize_expiredAttribute_notInjected() {
        SubjectAttribute expired = SubjectAttribute.builder()
                .id(UUID.randomUUID())
                .attributeName("extra_permissions")
                .attributeValue("price:BLOCK")
                .valueType("STRING")
                .validFrom(Instant.now().minusSeconds(3600))
                .validUntil(Instant.now().minusSeconds(1))  // expired 1 second ago
                .build();

        Subject subject = Subject.builder()
                .id(UUID.randomUUID())
                .externalId(EXT_ID)
                .attributes(Set.of(expired))
                .build();
        when(subjectRepository.findByExternalIdWithAttributes(TENANT, EXT_ID))
                .thenReturn(Optional.of(subject));
        when(pdp.evaluate(any())).thenReturn(permitResponse);

        authorizationService.authorize(request);

        ArgumentCaptor<AuthorizationRequest> captor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        verify(pdp).evaluate(captor.capture());
        // expired attribute must not be injected
        assertThat(captor.getValue().getSubjectAttributes()).doesNotContainKey("extra_permissions");
    }

    @Test
    void authorize_futureAttribute_notInjected() {
        SubjectAttribute future = SubjectAttribute.builder()
                .id(UUID.randomUUID())
                .attributeName("extra_permissions")
                .attributeValue("price:BLOCK")
                .valueType("STRING")
                .validFrom(Instant.now().plusSeconds(3600))  // starts in the future
                .build();

        Subject subject = Subject.builder()
                .id(UUID.randomUUID())
                .externalId(EXT_ID)
                .attributes(Set.of(future))
                .build();
        when(subjectRepository.findByExternalIdWithAttributes(TENANT, EXT_ID))
                .thenReturn(Optional.of(subject));
        when(pdp.evaluate(any())).thenReturn(permitResponse);

        authorizationService.authorize(request);

        ArgumentCaptor<AuthorizationRequest> captor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        verify(pdp).evaluate(captor.capture());
        assertThat(captor.getValue().getSubjectAttributes()).doesNotContainKey("extra_permissions");
    }

    @Test
    void authorize_validAttribute_withBoundaries_isInjected() {
        SubjectAttribute valid = SubjectAttribute.builder()
                .id(UUID.randomUUID())
                .attributeName("extra_permissions")
                .attributeValue("price:BLOCK")
                .valueType("STRING")
                .validFrom(Instant.now().minusSeconds(3600))
                .validUntil(Instant.now().plusSeconds(3600))
                .build();

        Subject subject = Subject.builder()
                .id(UUID.randomUUID())
                .externalId(EXT_ID)
                .attributes(Set.of(valid))
                .build();
        when(subjectRepository.findByExternalIdWithAttributes(TENANT, EXT_ID))
                .thenReturn(Optional.of(subject));
        when(pdp.evaluate(any())).thenReturn(permitResponse);

        authorizationService.authorize(request);

        ArgumentCaptor<AuthorizationRequest> captor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        verify(pdp).evaluate(captor.capture());
        assertThat(captor.getValue().getSubjectAttributes())
                .containsEntry("extra_permissions", "price:BLOCK");
    }

    // --- authorizeBatch ---

    @Test
    void authorizeBatch_enrichesAllRequests() {
        AuthorizationRequest req1 = AuthorizationRequest.builder()
                .tenantId(TENANT).externalSubjectId(EXT_ID)
                .resource("price").action("BLOCK").subjectAttributes(new HashMap<>()).build();
        AuthorizationRequest req2 = AuthorizationRequest.builder()
                .tenantId(TENANT).externalSubjectId("mahtab")
                .resource("flight").action("READ").subjectAttributes(new HashMap<>()).build();

        Subject shamimSubject = Subject.builder()
                .id(UUID.randomUUID()).externalId(EXT_ID)
                .attributes(Set.of(attribute("extra_permissions", "price:BLOCK"))).build();
        Subject mahtabSubject = Subject.builder()
                .id(UUID.randomUUID()).externalId("mahtab")
                .attributes(new HashSet<>()).build();

        when(subjectRepository.findByExternalIdWithAttributes(TENANT, EXT_ID))
                .thenReturn(Optional.of(shamimSubject));
        when(subjectRepository.findByExternalIdWithAttributes(TENANT, "mahtab"))
                .thenReturn(Optional.of(mahtabSubject));
        // authorizeBatch calls pdp.evaluateBatch, not pdp.evaluate
        when(pdp.evaluateBatch(anyList())).thenReturn(List.of(permitResponse, permitResponse));

        authorizationService.authorizeBatch(List.of(req1, req2));

        verify(subjectRepository).findByExternalIdWithAttributes(TENANT, EXT_ID);
        verify(subjectRepository).findByExternalIdWithAttributes(TENANT, "mahtab");
        verify(pdp).evaluateBatch(anyList());

        // Shamim's request should have the enriched attribute
        assertThat(req1.getSubjectAttributes()).containsEntry("extra_permissions", "price:BLOCK");
        // Mahtab's request should remain empty
        assertThat(req2.getSubjectAttributes()).isEmpty();
    }

    @Test
    void authorizeBatch_emptyList_returnsEmpty() {
        when(pdp.evaluateBatch(anyList())).thenReturn(List.of());
        List<AuthorizationResponse> results = authorizationService.authorizeBatch(List.of());
        assertThat(results).isEmpty();
        verifyNoInteractions(subjectRepository);
        verify(pdp).evaluateBatch(List.of());
    }
}
