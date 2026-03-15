package com.pss.authorization.cache;

import com.pss.authorization.domain.dto.ContextRoutingBitmap;
import com.pss.authorization.domain.dto.PermissionBitmap;
import com.pss.authorization.domain.dto.PolicyApplicabilityBitmap;
import com.pss.authorization.domain.model.abac.Policy;
import com.pss.authorization.domain.model.hybrid.AuthorizationContext;
import com.pss.authorization.domain.model.rbac.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Two-level cache manager providing ultra-fast authorization data access.
 * 
 * Strategy:
 * 1. Check L1 (Caffeine) first - ~0.1ms
 * 2. If miss, check L2 (Redis) - ~1ms
 * 3. If miss, load from DB and populate both caches
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TwoLevelCacheManager {

    private final CacheManager caffeineCacheManager;
    private final RedisCacheManager redisCacheManager;

    /**
     * Gets permission bitmap from cache with fallback.
     * O(1) lookup time target: < 0.5ms
     */
    public Optional<PermissionBitmap> getPermissionBitmap(String tenantId, UUID subjectId) {
        String key = buildKey(tenantId, subjectId.toString());

        // L1 lookup
        PermissionBitmap bitmap = getFromL1(CacheConfiguration.PERMISSION_BITMAP, key, PermissionBitmap.class);
        if (bitmap != null) {
            log.trace("L1 cache hit for permission bitmap: {}", key);
            return Optional.of(bitmap);
        }

        // L2 lookup
        bitmap = getFromL2(CacheConfiguration.PERMISSION_BITMAP, key, PermissionBitmap.class);
        if (bitmap != null) {
            log.trace("L2 cache hit for permission bitmap: {}", key);
            // Promote to L1
            putToL1(CacheConfiguration.PERMISSION_BITMAP, key, bitmap);
            return Optional.of(bitmap);
        }

        return Optional.empty();
    }

    /**
     * Stores permission bitmap in both cache levels.
     */
    public void putPermissionBitmap(String tenantId, UUID subjectId, PermissionBitmap bitmap) {
        String key = buildKey(tenantId, subjectId.toString());
        putToL1(CacheConfiguration.PERMISSION_BITMAP, key, bitmap);
        putToL2(CacheConfiguration.PERMISSION_BITMAP, key, bitmap);
    }

    /**
     * Gets subject roles from cache.
     */
    public Optional<Set<UUID>> getSubjectRoles(String tenantId, String externalSubjectId) {
        String key = buildKey(tenantId, externalSubjectId);

        @SuppressWarnings("unchecked")
        Set<UUID> roles = getFromL1(CacheConfiguration.SUBJECT_ROLES, key, Set.class);
        if (roles != null) {
            return Optional.of(roles);
        }

        roles = getFromL2(CacheConfiguration.SUBJECT_ROLES, key, Set.class);
        if (roles != null) {
            putToL1(CacheConfiguration.SUBJECT_ROLES, key, roles);
            return Optional.of(roles);
        }

        return Optional.empty();
    }

    /**
     * Stores subject roles in cache.
     */
    public void putSubjectRoles(String tenantId, String externalSubjectId, Set<UUID> roleIds) {
        String key = buildKey(tenantId, externalSubjectId);
        putToL1(CacheConfiguration.SUBJECT_ROLES, key, roleIds);
        putToL2(CacheConfiguration.SUBJECT_ROLES, key, roleIds);
    }

    /**
     * Gets applicable policies from cache.
     */
    public Optional<List<Policy>> getPoliciesByTarget(String tenantId, String resource, String action) {
        String key = buildKey(tenantId, resource, action);

        @SuppressWarnings("unchecked")
        List<Policy> policies = getFromL1(CacheConfiguration.POLICY_BY_TARGET, key, List.class);
        if (policies != null) {
            return Optional.of(policies);
        }

        policies = getFromL2(CacheConfiguration.POLICY_BY_TARGET, key, List.class);
        if (policies != null) {
            putToL1(CacheConfiguration.POLICY_BY_TARGET, key, policies);
            return Optional.of(policies);
        }

        return Optional.empty();
    }

    /**
     * Stores policies by target in cache.
     */
    public void putPoliciesByTarget(String tenantId, String resource, String action, List<Policy> policies) {
        String key = buildKey(tenantId, resource, action);
        putToL1(CacheConfiguration.POLICY_BY_TARGET, key, policies);
        putToL2(CacheConfiguration.POLICY_BY_TARGET, key, policies);
    }

    /**
     * Gets permission bit-index from cache (avoids repeated DB lookups per
     * evaluate()).
     */
    public Optional<Integer> getPermissionBitIndex(String tenantId, String resource, String action) {
        String key = buildKey(tenantId, resource, action);

        Integer bitIndex = getFromL1(CacheConfiguration.PERMISSION_LOOKUP, key, Integer.class);
        if (bitIndex != null) {
            return Optional.of(bitIndex);
        }

        bitIndex = getFromL2(CacheConfiguration.PERMISSION_LOOKUP, key, Integer.class);
        if (bitIndex != null) {
            putToL1(CacheConfiguration.PERMISSION_LOOKUP, key, bitIndex);
            return Optional.of(bitIndex);
        }

        return Optional.empty();
    }

    /**
     * Stores permission bit-index in both cache levels.
     */
    public void putPermissionBitIndex(String tenantId, String resource, String action, int bitIndex) {
        String key = buildKey(tenantId, resource, action);
        putToL1(CacheConfiguration.PERMISSION_LOOKUP, key, bitIndex);
        putToL2(CacheConfiguration.PERMISSION_LOOKUP, key, bitIndex);
    }

    /**
     * Gets authorization context from cache.
     */
    public Optional<AuthorizationContext> getAuthorizationContext(String tenantId, String resource) {
        String key = buildKey(tenantId, resource);

        AuthorizationContext context = getFromL1(CacheConfiguration.AUTHORIZATION_CONTEXT, key,
                AuthorizationContext.class);
        if (context != null) {
            return Optional.of(context);
        }

        context = getFromL2(CacheConfiguration.AUTHORIZATION_CONTEXT, key, AuthorizationContext.class);
        if (context != null) {
            putToL1(CacheConfiguration.AUTHORIZATION_CONTEXT, key, context);
            return Optional.of(context);
        }

        return Optional.empty();
    }

    /**
     * Stores authorization context in both cache levels.
     */
    public void putAuthorizationContext(String tenantId, String resource, AuthorizationContext context) {
        String key = buildKey(tenantId, resource);
        putToL1(CacheConfiguration.AUTHORIZATION_CONTEXT, key, context);
        putToL2(CacheConfiguration.AUTHORIZATION_CONTEXT, key, context);
    }

    /**
     * Gets PolicyApplicabilityBitmap from cache.
     */
    public Optional<PolicyApplicabilityBitmap> getPolicyApplicabilityBitmap(String tenantId) {
        String key = tenantId;

        PolicyApplicabilityBitmap bitmap = getFromL1(
                CacheConfiguration.POLICY_APPLICABILITY_BITMAP, key, PolicyApplicabilityBitmap.class);
        if (bitmap != null) {
            return Optional.of(bitmap);
        }

        bitmap = getFromL2(
                CacheConfiguration.POLICY_APPLICABILITY_BITMAP, key, PolicyApplicabilityBitmap.class);
        if (bitmap != null) {
            putToL1(CacheConfiguration.POLICY_APPLICABILITY_BITMAP, key, bitmap);
            return Optional.of(bitmap);
        }

        return Optional.empty();
    }

    /**
     * Stores PolicyApplicabilityBitmap in both cache levels.
     */
    public void putPolicyApplicabilityBitmap(String tenantId, PolicyApplicabilityBitmap bitmap) {
        String key = tenantId;
        putToL1(CacheConfiguration.POLICY_APPLICABILITY_BITMAP, key, bitmap);
        putToL2(CacheConfiguration.POLICY_APPLICABILITY_BITMAP, key, bitmap);
    }

    /**
     * Gets ContextRoutingBitmap from cache.
     */
    public Optional<ContextRoutingBitmap> getContextRoutingBitmap(String tenantId) {
        String key = tenantId;

        ContextRoutingBitmap bitmap = getFromL1(
                CacheConfiguration.CONTEXT_ROUTING_BITMAP, key, ContextRoutingBitmap.class);
        if (bitmap != null) {
            return Optional.of(bitmap);
        }

        bitmap = getFromL2(
                CacheConfiguration.CONTEXT_ROUTING_BITMAP, key, ContextRoutingBitmap.class);
        if (bitmap != null) {
            putToL1(CacheConfiguration.CONTEXT_ROUTING_BITMAP, key, bitmap);
            return Optional.of(bitmap);
        }

        return Optional.empty();
    }

    /**
     * Stores ContextRoutingBitmap in both cache levels.
     */
    public void putContextRoutingBitmap(String tenantId, ContextRoutingBitmap bitmap) {
        String key = tenantId;
        putToL1(CacheConfiguration.CONTEXT_ROUTING_BITMAP, key, bitmap);
        putToL2(CacheConfiguration.CONTEXT_ROUTING_BITMAP, key, bitmap);
    }

    /**
     * Invalidates all caches for a tenant.
     */
    public void invalidateTenant(String tenantId) {
        log.info("Invalidating all caches for tenant: {}", tenantId);
        // In production, implement selective invalidation using Redis SCAN
        for (String cacheName : List.of(
                CacheConfiguration.SUBJECT_ROLES,
                CacheConfiguration.SUBJECT_PERMISSIONS,
                CacheConfiguration.PERMISSION_BITMAP,
                CacheConfiguration.POLICIES,
                CacheConfiguration.POLICY_BY_TARGET,
                CacheConfiguration.AUTHORIZATION_CONTEXT)) {

            Cache l1Cache = caffeineCacheManager.getCache(cacheName);
            if (l1Cache != null) {
                l1Cache.clear();
            }
        }
    }

    /**
     * Invalidates caches for a specific subject.
     */
    public void invalidateSubject(String tenantId, String externalSubjectId) {
        String key = buildKey(tenantId, externalSubjectId);
        evictFromBoth(CacheConfiguration.SUBJECT_ROLES, key);
        evictFromBoth(CacheConfiguration.PERMISSION_BITMAP, key);
        evictFromBoth(CacheConfiguration.SUBJECT_PERMISSIONS, key);
    }

    /**
     * Invalidates policy caches.
     */
    public void invalidatePolicies(String tenantId) {
        Cache l1Cache = caffeineCacheManager.getCache(CacheConfiguration.POLICIES);
        if (l1Cache != null) {
            l1Cache.clear();
        }
        l1Cache = caffeineCacheManager.getCache(CacheConfiguration.POLICY_BY_TARGET);
        if (l1Cache != null) {
            l1Cache.clear();
        }
    }

    // Helper methods

    private <T> T getFromL1(String cacheName, String key, Class<T> type) {
        Cache cache = caffeineCacheManager.getCache(cacheName);
        if (cache != null) {
            Cache.ValueWrapper wrapper = cache.get(key);
            if (wrapper != null) {
                return type.cast(wrapper.get());
            }
        }
        return null;
    }

    private <T> T getFromL2(String cacheName, String key, Class<T> type) {
        Cache cache = redisCacheManager.getCache(cacheName);
        if (cache != null) {
            Cache.ValueWrapper wrapper = cache.get(key);
            if (wrapper != null) {
                return type.cast(wrapper.get());
            }
        }
        return null;
    }

    private void putToL1(String cacheName, String key, Object value) {
        Cache cache = caffeineCacheManager.getCache(cacheName);
        if (cache != null) {
            cache.put(key, value);
        }
    }

    private void putToL2(String cacheName, String key, Object value) {
        Cache cache = redisCacheManager.getCache(cacheName);
        if (cache != null) {
            cache.put(key, value);
        }
    }

    private void evictFromBoth(String cacheName, String key) {
        Cache l1Cache = caffeineCacheManager.getCache(cacheName);
        if (l1Cache != null) {
            l1Cache.evict(key);
        }
        Cache l2Cache = redisCacheManager.getCache(cacheName);
        if (l2Cache != null) {
            l2Cache.evict(key);
        }
    }

    private String buildKey(String... parts) {
        return String.join(":", parts);
    }
}
