package com.pss.authorization.domain.engine;

import com.pss.authorization.cache.TwoLevelCacheManager;
import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.dto.AuthorizationResponse.Decision;
import com.pss.authorization.domain.dto.PermissionBitmap;
import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import com.pss.authorization.domain.model.rbac.Permission;
import com.pss.authorization.domain.model.rbac.Role;
import com.pss.authorization.domain.model.rbac.Subject;
import com.pss.authorization.persistence.repository.PermissionRepository;
import com.pss.authorization.persistence.repository.SubjectRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

/**
 * RBAC (Role-Based Access Control) Engine.
 * 
 * Evaluation Strategy:
 * 1. Load permission bitmap from cache (O(1) lookup)
 * 2. If cache miss, compute bitmap from roles and cache it
 * 3. Check if required permission bit is set
 * 
 * Target latency: < 2ms
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RbacEngine implements AuthorizationEngine {

    private final TwoLevelCacheManager cacheManager;
    private final SubjectRepository subjectRepository;
    private final PermissionRepository permissionRepository;

    @Override
    public String getEngineType() {
        return "RBAC";
    }

    @Override
    public boolean canHandle(AuthorizationRequest request) {
        return request.getTenantId() != null &&
                (request.getSubjectId() != null || request.getExternalSubjectId() != null);
    }

    @Override
    @Transactional(readOnly = true)
    public AuthorizationResponse evaluate(AuthorizationRequest request) {
        long startTime = System.nanoTime();

        try {
            String tenantId = request.getTenantId();
            String externalSubjectId = request.getExternalSubjectId();
            String resource = request.getResource();
            String action = request.getAction();

            // Step 1: Try to get permission bitmap from cache
            Optional<PermissionBitmap> cachedBitmap = cacheManager.getPermissionBitmap(
                    tenantId,
                    UUID.nameUUIDFromBytes((tenantId + ":" + externalSubjectId).getBytes(StandardCharsets.UTF_8)));

            PermissionBitmap bitmap;
            boolean cached = cachedBitmap.isPresent();

            if (cached) {
                bitmap = cachedBitmap.get();
            } else {
                // Step 2: Cache miss - compute bitmap
                bitmap = computePermissionBitmap(tenantId, externalSubjectId);
                if (bitmap == null) {
                    return buildResponse(Decision.DENY, "Subject not found", startTime, false, null);
                }

                // Store in cache for future requests
                cacheManager.putPermissionBitmap(tenantId, bitmap.getSubjectId(), bitmap);
            }

            // Step 3: Find permission bit index for resource:action (cached)
            Optional<Integer> cachedBitIndex = cacheManager.getPermissionBitIndex(tenantId, resource, action);
            final int bitIndex;
            if (cachedBitIndex.isPresent()) {
                bitIndex = cachedBitIndex.get();
            } else {
                Optional<Permission> permission = permissionRepository.findByResourceAndAction(
                        tenantId, resource, action);
                if (permission.isEmpty()) {
                    return buildResponse(Decision.NOT_APPLICABLE,
                            "Permission not defined: " + resource + ":" + action,
                            startTime, cached, cached ? "L1" : null);
                }
                bitIndex = permission.get().getBitIndex();
                cacheManager.putPermissionBitIndex(tenantId, resource, action, bitIndex);
            }

            // Step 4: O(1) bitmap check
            boolean hasPermission = bitmap.hasPermission(bitIndex);

            if (hasPermission) {
                return buildResponse(Decision.PERMIT,
                        "Permission granted via role assignment",
                        startTime, cached, cached ? "L1" : null);
            } else {
                return buildResponse(Decision.DENY,
                        "Permission not granted: " + resource + ":" + action,
                        startTime, cached, cached ? "L1" : null);
            }

        } catch (Exception e) {
            log.error("RBAC evaluation error", e);
            return buildResponse(Decision.INDETERMINATE,
                    "Evaluation error: " + e.getMessage(),
                    startTime, false, null);
        }
    }

    /**
     * Computes permission bitmap for a subject by aggregating all role permissions.
     */
    private PermissionBitmap computePermissionBitmap(String tenantId, String externalSubjectId) {
        Optional<Subject> subjectOpt = subjectRepository.findByExternalIdWithRolesAndPermissions(
                tenantId, externalSubjectId);

        if (subjectOpt.isEmpty()) {
            return null;
        }

        Subject subject = subjectOpt.get();

        // Collect all permissions directly from eagerly-fetched roles
        // (findByExternalIdWithRolesAndPermissions already JOIN FETCHes roles +
        // permissions)
        Set<Permission> allPermissions = new HashSet<>();
        for (Role role : subject.getRoles()) {
            allPermissions.addAll(role.getAllPermissions());
        }

        Set<UUID> roleIds = subject.getRoles().stream()
                .map(Role::getId)
                .collect(Collectors.toSet());

        // Build bitmap
        BitSet permissionBits = new BitSet();
        for (Permission permission : allPermissions) {
            permissionBits.set(permission.getBitIndex());
        }

        return PermissionBitmap.builder()
                .subjectId(subject.getId())
                .tenantId(tenantId)
                .permissions(permissionBits)
                .roleIds(roleIds)
                .version(System.currentTimeMillis())
                .computedAt(System.currentTimeMillis())
                .build();
    }

    /**
     * Builds authorization response with timing information.
     */
    private AuthorizationResponse buildResponse(
            Decision decision,
            String reason,
            long startTimeNanos,
            boolean cached,
            String cacheLevel) {

        double evaluationTimeMs = (System.nanoTime() - startTimeNanos) / 1_000_000.0;

        return AuthorizationResponse.builder()
                .decision(decision)
                .mode(AuthorizationMode.RBAC)
                .reason(reason)
                .determinedBy("RBAC Engine")
                .evaluationTimeMs(evaluationTimeMs)
                .cached(cached)
                .cacheLevel(cacheLevel)
                .build();
    }
}
