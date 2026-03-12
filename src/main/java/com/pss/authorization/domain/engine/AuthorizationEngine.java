package com.pss.authorization.domain.engine;

import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;

/**
 * Base interface for authorization engines.
 * Implementations: RbacEngine, AbacEngine, HybridEngine
 */
public interface AuthorizationEngine {

    /**
     * Evaluates an authorization request and returns a decision.
     * Target latency: < 5ms
     *
     * @param request The authorization request with subject, resource, action, and
     *                attributes
     * @return The authorization decision with reason and timing info
     */
    AuthorizationResponse evaluate(AuthorizationRequest request);

    /**
     * Returns the engine type identifier.
     */
    String getEngineType();

    /**
     * Checks if this engine can handle the given request.
     */
    boolean canHandle(AuthorizationRequest request);
}
