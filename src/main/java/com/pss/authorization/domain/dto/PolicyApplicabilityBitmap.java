package com.pss.authorization.domain.dto;

import com.pss.authorization.domain.model.abac.Policy;
import lombok.Builder;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Pre-computed bitmap mapping resource:action pairs to applicable ABAC
 * policies.
 * Eliminates the need for PolicyRepository.findApplicablePolicies() DB calls.
 *
 * <p>
 * Each active policy is assigned a sequential bitIndex. For every known
 * resource:action combination, a BitSet records which policies are applicable.
 * </p>
 *
 * <p>
 * Stored per-tenant in the two-level cache.
 * </p>
 */
@Builder
public record PolicyApplicabilityBitmap(
        String tenantId,
        List<Policy> policyIndex,
        Map<String, BitSet> exactTargetMap,
        List<WildcardEntry> wildcardPatterns,
        BitSet globalPolicies,
        long version,
        long computedAt) {
    public PolicyApplicabilityBitmap {
        if (policyIndex == null)
            policyIndex = new ArrayList<>();
        if (exactTargetMap == null)
            exactTargetMap = new HashMap<>();
        if (wildcardPatterns == null)
            wildcardPatterns = new ArrayList<>();
        if (globalPolicies == null)
            globalPolicies = new BitSet();
    }

    /**
     * O(1) lookup for applicable policies given a resource:action pair.
     */
    public List<Policy> getApplicablePolicies(String resource, String action) {
        BitSet combined = new BitSet();

        // 1. Exact match: "resource:action"
        var exactKey = resource + ":" + action;
        BitSet exact = exactTargetMap.get(exactKey);
        if (exact != null) {
            combined.or(exact);
        }

        // 2. Resource-wildcard match: "resource:*"
        var resourceWild = resource + ":*";
        BitSet resWild = exactTargetMap.get(resourceWild);
        if (resWild != null) {
            combined.or(resWild);
        }

        // 3. Prefix wildcard patterns (e.g., policy targets "orders:*" and resource is
        // "orders:123")
        for (WildcardEntry entry : wildcardPatterns) {
            if (resource.startsWith(entry.prefix())) {
                if ("*".equals(entry.action()) || entry.action().equals(action)) {
                    combined.or(entry.policyBits());
                }
            }
        }

        // 4. Global policies ("*" resource, matching action)
        combined.or(globalPolicies);

        // Resolve bit indexes to Policy objects
        if (combined.isEmpty()) {
            return List.of();
        }

        List<Policy> result = new ArrayList<>();
        for (int i = combined.nextSetBit(0); i >= 0; i = combined.nextSetBit(i + 1)) {
            if (i < policyIndex.size()) {
                result.add(policyIndex.get(i));
            }
        }
        return result;
    }

    /**
     * Checks if there are any applicable policies for a resource:action pair.
     * Faster than getApplicablePolicies() when you only need a boolean check.
     */
    public boolean hasApplicablePolicies(String resource, String action) {
        var exactKey = resource + ":" + action;
        BitSet exact = exactTargetMap.get(exactKey);
        if (exact != null && !exact.isEmpty())
            return true;

        var resourceWild = resource + ":*";
        BitSet resWild = exactTargetMap.get(resourceWild);
        if (resWild != null && !resWild.isEmpty())
            return true;

        for (WildcardEntry entry : wildcardPatterns) {
            if (resource.startsWith(entry.prefix()) &&
                    ("*".equals(entry.action()) || entry.action().equals(action))) {
                return true;
            }
        }

        return !globalPolicies.isEmpty();
    }

    /**
     * Entry for prefix-based wildcard matching.
     * E.g., a policy targeting "orders:*" becomes prefix="orders:" action="*".
     */
    @Builder
    public record WildcardEntry(String prefix, String action, BitSet policyBits) {
    }
}
