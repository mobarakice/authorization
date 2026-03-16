package com.pss.authorization.service;

import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.dto.SubjectAttributeDto;
import com.pss.authorization.domain.xacml.PolicyDecisionPoint;
import com.pss.authorization.cache.TwoLevelCacheManager;
import com.pss.authorization.persistence.repository.SubjectRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service layer for authorization operations.
 *
 * Responsibilities:
 * - Enriches requests with DB-stored subject attributes before PDP evaluation.
 * This enables ABAC policies to evaluate server-side attributes (e.g.,
 * extra_permissions)
 * without requiring callers to know about internal permission grants.
 * - Owns the @Transactional boundary for all authorization reads.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthorizationService {

    private final PolicyDecisionPoint pdp;
    private final SubjectRepository subjectRepository;
    private final TwoLevelCacheManager cacheManager;

    @Transactional(readOnly = true)
    public AuthorizationResponse authorize(AuthorizationRequest request) {
        var enrichedRequest = enrichSubjectAttributes(request);
        return pdp.evaluate(enrichedRequest);
    }

    @Transactional(readOnly = true)
    public List<AuthorizationResponse> authorizeBatch(List<AuthorizationRequest> requests) {
        List<AuthorizationRequest> enrichedRequests = requests.stream()
                .map(this::enrichSubjectAttributes)
                .toList();
        return pdp.evaluateBatch(enrichedRequests);
    }

    /**
     * Loads subject attributes from DB and merges into the request.
     * DB-stored attributes are added with putIfAbsent — caller-provided values take
     * precedence
     * for context attributes (location, device_type, etc.) but the caller never
     * knows about
     * internal grants like extra_permissions, so those always come from DB.
     *
     * Only valid attributes (within valid_from/valid_until window) are applied.
     */
    private AuthorizationRequest enrichSubjectAttributes(AuthorizationRequest request) {
        var tenantId = request.tenantId();
        var externalId = request.externalSubjectId();
        if (tenantId == null || externalId == null) {
            return request;
        }

        List<SubjectAttributeDto> cachedAttributes = cacheManager.getSubjectAttributes(tenantId, externalId)
                .orElse(null);

        if (cachedAttributes == null) {
            var subjectOpt = subjectRepository.findByExternalIdWithAttributes(tenantId, externalId);
            if (subjectOpt.isPresent()) {
                cachedAttributes = subjectOpt.get().getAttributes().stream()
                        .map(attr -> new SubjectAttributeDto(
                                attr.getAttributeName(),
                                attr.getAttributeValue(),
                                attr.getValidFrom(),
                                attr.getValidUntil()))
                        .toList();
                cacheManager.putSubjectAttributes(tenantId, externalId, cachedAttributes);
            } else {
                return request;
            }
        }

        if (cachedAttributes.isEmpty()) {
            return request;
        }

        Map<String, Object> enriched = new HashMap<>(
                request.subjectAttributes() != null
                        ? request.subjectAttributes()
                        : Map.of());

        cachedAttributes.stream()
                .filter(SubjectAttributeDto::isValid)
                .forEach(attr -> enriched.putIfAbsent(attr.name(), attr.value()));

        return request.toBuilder().subjectAttributes(enriched).build();
    }
}
