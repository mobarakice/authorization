package com.pss.authorization.domain.model.abac;

/**
 * Algorithm for combining multiple policy/rule decisions.
 * Based on XACML combining algorithms.
 */
public enum CombiningAlgorithm {

    /**
     * First applicable policy/rule wins.
     */
    FIRST_APPLICABLE,

    /**
     * If any policy denies, result is DENY.
     */
    DENY_OVERRIDES,

    /**
     * If any policy permits, result is PERMIT.
     */
    PERMIT_OVERRIDES,

    /**
     * If any policy denies, result is DENY (unless no policy applies).
     */
    DENY_UNLESS_PERMIT,

    /**
     * If any policy permits, result is PERMIT (unless no policy applies).
     */
    PERMIT_UNLESS_DENY,

    /**
     * All policies must return the same decision.
     */
    ONLY_ONE_APPLICABLE
}
