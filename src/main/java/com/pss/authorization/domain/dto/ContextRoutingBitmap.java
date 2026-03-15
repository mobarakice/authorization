package com.pss.authorization.domain.dto;

import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import com.pss.authorization.domain.model.hybrid.CombiningStrategy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Builder;

/**
 * Pre-computed routing table mapping resources to their authorization context
 * configuration.
 * Eliminates the need for AuthorizationContextRepository.findMatchingContexts()
 * DB calls.
 *
 * <p>
 * Resolution order:
 * </p>
 * <ol>
 * <li>Exact match (e.g., "orders" → config)</li>
 * <li>Prefix match (e.g., "orders:*" matches "orders:123")</li>
 * <li>Default config (CombiningStrategy.AND)</li>
 * </ol>
 *
 * <p>
 * Stored per-tenant in the two-level cache.
 * </p>
 */
@Builder
public record ContextRoutingBitmap(
        String tenantId,
        Map<String, ContextConfig> exactMatches,
        List<PrefixEntry> prefixPatterns,
        ContextConfig defaultConfig,
        long version,
        long computedAt) {
    public ContextRoutingBitmap {
        if (exactMatches == null)
            exactMatches = new HashMap<>();
        if (prefixPatterns == null)
            prefixPatterns = new ArrayList<>();
        if (defaultConfig == null)
            defaultConfig = new ContextConfig(
                    CombiningStrategy.AND, AuthorizationMode.HYBRID);
    }

    /**
     * Resolves the authorization context config for a resource.
     * O(1) for exact matches, O(n) for prefix patterns (n is typically < 20).
     */
    public ContextConfig resolve(String resource) {
        // 1. Exact match — O(1)
        ContextConfig exact = exactMatches.get(resource);
        if (exact != null) {
            return exact;
        }

        // 2. Prefix match — scan sorted patterns (most specific first)
        for (PrefixEntry entry : prefixPatterns) {
            if (resource.startsWith(entry.prefix())) {
                return entry.config();
            }
        }

        // 3. Default
        return defaultConfig;
    }

    /**
     * Configuration for an authorization context.
     */
    @Builder
    public record ContextConfig(CombiningStrategy strategy, AuthorizationMode mode) {
    }

    /**
     * Entry for prefix-based wildcard matching, sorted by priority.
     */
    @Builder
    public record PrefixEntry(String prefix, int priority, ContextConfig config) {
    }
}
