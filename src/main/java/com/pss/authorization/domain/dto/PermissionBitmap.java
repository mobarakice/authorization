package com.pss.authorization.domain.dto;

import lombok.Builder;

import java.util.BitSet;
import java.util.Set;
import java.util.UUID;

/**
 * Pre-computed permission bitmap for O(1) permission checks.
 * Stored in cache for fast authorization without database lookups.
 */
@Builder
public record PermissionBitmap(
        UUID subjectId,
        String tenantId,
        BitSet permissions,
        Set<UUID> roleIds,
        long version,
        long computedAt) {

    /**
     * Checks if this bitmap grants the specified permission.
     * O(1) lookup time.
     */
    public boolean hasPermission(int permissionBitIndex) {
        return permissions != null && permissions.get(permissionBitIndex);
    }

    /**
     * Checks if this bitmap grants any of the specified permissions.
     */
    public boolean hasAnyPermission(int... permissionBitIndexes) {
        if (permissions == null)
            return false;
        for (int index : permissionBitIndexes) {
            if (permissions.get(index)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if this bitmap grants all of the specified permissions.
     */
    public boolean hasAllPermissions(int... permissionBitIndexes) {
        if (permissions == null)
            return false;
        for (int index : permissionBitIndexes) {
            if (!permissions.get(index)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns the total number of granted permissions.
     */
    public int permissionCount() {
        return permissions != null ? permissions.cardinality() : 0;
    }
}
