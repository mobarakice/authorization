package com.pss.authorization.domain.model.hybrid;

/**
 * Authorization mode determining which engine(s) to use.
 */
public enum AuthorizationMode {

    /**
     * Use only RBAC for authorization.
     */
    RBAC,

    /**
     * Use only ABAC for authorization.
     */
    ABAC,

    /**
     * Use both RBAC and ABAC with a combining strategy.
     */
    HYBRID
}
