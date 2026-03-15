package com.pss.authorization.domain.dto;

import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import com.pss.authorization.domain.model.hybrid.CombiningStrategy;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.*;

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
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ContextRoutingBitmap {

    private String tenantId;

    /**
     * Exact resource → context config (highest priority wins).
     */
    @Builder.Default
    private Map<String, ContextConfig> exactMatches = new HashMap<>();

    /**
     * Prefix patterns sorted by priority (lower = higher precedence).
     * E.g., "orders:" prefix matches "orders:123".
     */
    @Builder.Default
    private List<PrefixEntry> prefixPatterns = new ArrayList<>();

    /**
     * Default config when no context matches.
     */
    @Builder.Default
    private ContextConfig defaultConfig = new ContextConfig(
            CombiningStrategy.AND, AuthorizationMode.HYBRID);

    private long version;
    private long computedAt;

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
            if (resource.startsWith(entry.prefix)) {
                return entry.config;
            }
        }

        // 3. Default
        return defaultConfig;
    }

    /**
     * Configuration for an authorization context.
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class ContextConfig {
        private CombiningStrategy strategy;
        private AuthorizationMode mode;
    }

    /**
     * Entry for prefix-based wildcard matching, sorted by priority.
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class PrefixEntry {
        private String prefix;
        private int priority;
        private ContextConfig config;
    }
}
