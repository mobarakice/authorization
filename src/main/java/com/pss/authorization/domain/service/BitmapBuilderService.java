package com.pss.authorization.domain.service;

import com.pss.authorization.domain.dto.ContextRoutingBitmap;
import com.pss.authorization.domain.dto.ContextRoutingBitmap.ContextConfig;
import com.pss.authorization.domain.dto.ContextRoutingBitmap.PrefixEntry;
import com.pss.authorization.domain.dto.PolicyApplicabilityBitmap;
import com.pss.authorization.domain.dto.PolicyApplicabilityBitmap.WildcardEntry;
import com.pss.authorization.domain.model.abac.Policy;
import com.pss.authorization.domain.model.hybrid.AuthorizationContext;
import com.pss.authorization.domain.model.hybrid.AuthorizationMode;
import com.pss.authorization.domain.model.hybrid.CombiningStrategy;
import com.pss.authorization.persistence.repository.AuthorizationContextRepository;
import com.pss.authorization.persistence.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

/**
 * Central service for building all bitmap types.
 * Loads data from DB in bulk and pre-computes bitmaps for O(1) authorization
 * lookups.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BitmapBuilderService {

    private final PolicyRepository policyRepository;
    private final AuthorizationContextRepository contextRepository;

    /**
     * Builds a PolicyApplicabilityBitmap for a tenant.
     * Loads all active policies once and indexes them by target resource:action.
     *
     * @param tenantId tenant identifier
     * @return pre-computed bitmap (1 DB call)
     */
    @Transactional(readOnly = true)
    public PolicyApplicabilityBitmap buildPolicyBitmap(String tenantId) {
        log.debug("Building PolicyApplicabilityBitmap for tenant: {}", tenantId);
        long start = System.nanoTime();

        List<Policy> allPolicies = policyRepository.findActivePoliciesWithRules(tenantId);

        // Assign bit indexes if not yet assigned
        List<Policy> policyIndex = new ArrayList<>();
        Map<String, BitSet> exactTargetMap = new HashMap<>();
        List<WildcardEntry> wildcardPatterns = new ArrayList<>();
        BitSet globalPolicies = new BitSet();

        for (int i = 0; i < allPolicies.size(); i++) {
            Policy policy = allPolicies.get(i);

            // Use existing bitIndex if available, otherwise use list position
            int bitIdx = policy.getBitIndex() != null ? policy.getBitIndex() : i;

            // Ensure policyIndex is large enough
            while (policyIndex.size() <= bitIdx) {
                policyIndex.add(null);
            }
            policyIndex.set(bitIdx, policy);

            String targetResource = policy.getTargetResource();
            String targetAction = policy.getTargetAction();

            if ("*".equals(targetResource)) {
                // Global policy — applies to all resources
                globalPolicies.set(bitIdx);
            } else if (targetResource.endsWith(":*")) {
                // Prefix wildcard: "orders:*" → prefix "orders:"
                String prefix = targetResource.substring(0, targetResource.length() - 1);
                WildcardEntry entry = findOrCreateWildcard(wildcardPatterns, prefix, targetAction);
                entry.getPolicyBits().set(bitIdx);
            } else {
                // Exact match: "orders:READ" or "orders:*"
                String key = targetResource + ":" + targetAction;
                exactTargetMap.computeIfAbsent(key, k -> new BitSet()).set(bitIdx);

                // Also index under resource:* if action is wildcard
                if ("*".equals(targetAction)) {
                    exactTargetMap.computeIfAbsent(targetResource + ":*", k -> new BitSet()).set(bitIdx);
                }
            }
        }

        // Sort wildcard patterns by prefix length (longer = more specific first)
        wildcardPatterns.sort((a, b) -> Integer.compare(b.getPrefix().length(), a.getPrefix().length()));

        double buildTimeMs = (System.nanoTime() - start) / 1_000_000.0;
        log.info("PolicyApplicabilityBitmap built for tenant {} in {}ms: {} policies, {} exact targets, {} wildcards",
                tenantId, String.format("%.2f", buildTimeMs),
                allPolicies.size(), exactTargetMap.size(), wildcardPatterns.size());

        return PolicyApplicabilityBitmap.builder()
                .tenantId(tenantId)
                .policyIndex(policyIndex)
                .exactTargetMap(exactTargetMap)
                .wildcardPatterns(wildcardPatterns)
                .globalPolicies(globalPolicies)
                .version(System.currentTimeMillis())
                .computedAt(System.currentTimeMillis())
                .build();
    }

    /**
     * Builds a ContextRoutingBitmap for a tenant.
     * Loads all active authorization contexts once and indexes by resource pattern.
     *
     * @param tenantId tenant identifier
     * @return pre-computed routing table (1 DB call)
     */
    @Transactional(readOnly = true)
    public ContextRoutingBitmap buildContextRoutingBitmap(String tenantId) {
        log.debug("Building ContextRoutingBitmap for tenant: {}", tenantId);
        long start = System.nanoTime();

        List<AuthorizationContext> contexts = contextRepository.findActiveContextsWithRules(tenantId);

        Map<String, ContextConfig> exactMatches = new HashMap<>();
        List<PrefixEntry> prefixPatterns = new ArrayList<>();
        ContextConfig defaultConfig = new ContextConfig(CombiningStrategy.AND, AuthorizationMode.HYBRID);

        for (AuthorizationContext ctx : contexts) {
            CombiningStrategy strategy = ctx.getCombiningStrategy() != null
                    ? ctx.getCombiningStrategy()
                    : CombiningStrategy.AND;
            AuthorizationMode mode = ctx.getMode() != null
                    ? ctx.getMode()
                    : AuthorizationMode.HYBRID;

            ContextConfig config = new ContextConfig(strategy, mode);
            String pattern = ctx.getResourcePattern();

            if ("*".equals(pattern)) {
                // Global default — only if higher priority than existing default
                defaultConfig = config;
            } else if (pattern.endsWith(":*")) {
                // Prefix pattern: "orders:*" → prefix "orders:"
                String prefix = pattern.substring(0, pattern.length() - 1);
                prefixPatterns.add(PrefixEntry.builder()
                        .prefix(prefix)
                        .priority(ctx.getPriority())
                        .config(config)
                        .build());
            } else {
                // Exact match
                exactMatches.put(pattern, config);
            }
        }

        // Sort prefix patterns: lower priority number = higher precedence
        prefixPatterns.sort(Comparator.comparingInt(PrefixEntry::getPriority));

        double buildTimeMs = (System.nanoTime() - start) / 1_000_000.0;
        log.info("ContextRoutingBitmap built for tenant {} in {}ms: {} exact, {} prefix, default={}",
                tenantId, String.format("%.2f", buildTimeMs),
                exactMatches.size(), prefixPatterns.size(), defaultConfig.getStrategy());

        return ContextRoutingBitmap.builder()
                .tenantId(tenantId)
                .exactMatches(exactMatches)
                .prefixPatterns(prefixPatterns)
                .defaultConfig(defaultConfig)
                .version(System.currentTimeMillis())
                .computedAt(System.currentTimeMillis())
                .build();
    }

    private WildcardEntry findOrCreateWildcard(List<WildcardEntry> patterns, String prefix, String action) {
        for (WildcardEntry entry : patterns) {
            if (entry.getPrefix().equals(prefix) && entry.getAction().equals(action)) {
                return entry;
            }
        }
        WildcardEntry entry = WildcardEntry.builder()
                .prefix(prefix)
                .action(action)
                .policyBits(new BitSet())
                .build();
        patterns.add(entry);
        return entry;
    }
}
