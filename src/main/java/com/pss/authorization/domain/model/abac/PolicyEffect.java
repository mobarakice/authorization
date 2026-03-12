package com.pss.authorization.domain.model.abac;

/**
 * Policy effect - the outcome when a policy matches.
 */
public enum PolicyEffect {

    /**
     * Allow the access request.
     */
    PERMIT,

    /**
     * Deny the access request.
     */
    DENY
}
