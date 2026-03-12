package com.pss.authorization.domain.model.hybrid;

/**
 * Strategy for combining RBAC and ABAC decisions in hybrid mode.
 */
public enum CombiningStrategy {

    /**
     * Both RBAC and ABAC must permit.
     */
    AND,

    /**
     * Either RBAC or ABAC must permit.
     */
    OR,

    /**
     * Check RBAC first; if permitted, check ABAC.
     * Short-circuits on RBAC deny.
     */
    RBAC_FIRST,

    /**
     * Check ABAC first; if permitted, check RBAC.
     * Short-circuits on ABAC deny.
     */
    ABAC_FIRST,

    /**
     * RBAC is required, ABAC adds constraints.
     * RBAC must permit AND ABAC must not deny.
     */
    RBAC_REQUIRED_ABAC_CONSTRAINS,

    /**
     * ABAC is primary, RBAC is fallback.
     * Use ABAC if applicable policies exist, otherwise use RBAC.
     */
    ABAC_PRIMARY_RBAC_FALLBACK
}
