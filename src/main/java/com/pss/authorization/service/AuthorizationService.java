package com.pss.authorization.service;

import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.model.rbac.SubjectAttribute;
import com.pss.authorization.domain.xacml.PolicyDecisionPoint;
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
 *   This enables ABAC policies to evaluate server-side attributes (e.g., extra_permissions)
 *   without requiring callers to know about internal permission grants.
 * - Owns the @Transactional boundary for all authorization reads.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthorizationService {

    private final PolicyDecisionPoint pdp;
    private final SubjectRepository subjectRepository;

    @Transactional(readOnly = true)
    public AuthorizationResponse authorize(AuthorizationRequest request) {
        enrichSubjectAttributes(request);
        return pdp.evaluate(request);
    }

    @Transactional(readOnly = true)
    public List<AuthorizationResponse> authorizeBatch(List<AuthorizationRequest> requests) {
        requests.forEach(this::enrichSubjectAttributes);
        return pdp.evaluateBatch(requests);
    }

    /**
     * Loads subject attributes from DB and merges into the request.
     * DB-stored attributes are added with putIfAbsent — caller-provided values take precedence
     * for context attributes (location, device_type, etc.) but the caller never knows about
     * internal grants like extra_permissions, so those always come from DB.
     *
     * Only valid attributes (within valid_from/valid_until window) are applied.
     */
    private void enrichSubjectAttributes(AuthorizationRequest request) {
        String tenantId = request.getTenantId();
        String externalId = request.getExternalSubjectId();
        if (tenantId == null || externalId == null) {
            return;
        }

        subjectRepository.findByExternalIdWithAttributes(tenantId, externalId)
                .ifPresent(subject -> {
                    if (subject.getAttributes().isEmpty()) {
                        return;
                    }

                    Map<String, Object> enriched = new HashMap<>(
                            request.getSubjectAttributes() != null
                                    ? request.getSubjectAttributes()
                                    : Map.of());

                    for (SubjectAttribute attr : subject.getAttributes()) {
                        if (attr.isValid()) {
                            enriched.putIfAbsent(attr.getAttributeName(), attr.getAttributeValue());
                        }
                    }

                    request.setSubjectAttributes(enriched);
                });
    }
}
