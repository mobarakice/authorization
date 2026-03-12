package com.pss.authorization.persistence.repository;

import com.pss.authorization.domain.model.hybrid.AuthorizationContext;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for AuthorizationContext entity.
 */
@Repository
public interface AuthorizationContextRepository extends JpaRepository<AuthorizationContext, UUID> {

    Optional<AuthorizationContext> findByTenantIdAndName(String tenantId, String name);

    @Query("""
            SELECT c FROM AuthorizationContext c
            LEFT JOIN FETCH c.rules r
            LEFT JOIN FETCH r.role
            LEFT JOIN FETCH r.policy
            WHERE c.tenantId = :tenantId
            AND c.active = true
            ORDER BY c.priority ASC
            """)
    List<AuthorizationContext> findActiveContextsWithRules(@Param("tenantId") String tenantId);

    @Query("""
            SELECT c FROM AuthorizationContext c
            LEFT JOIN FETCH c.rules
            WHERE c.tenantId = :tenantId
            AND c.active = true
            AND (c.resourcePattern = '*'
                 OR c.resourcePattern = :resource
                 OR (c.resourcePattern LIKE '%:*' AND :resource LIKE CONCAT(SUBSTRING(c.resourcePattern, 1, LENGTH(c.resourcePattern) - 1), '%')))
            ORDER BY c.priority ASC
            """)
    List<AuthorizationContext> findMatchingContexts(
            @Param("tenantId") String tenantId,
            @Param("resource") String resource);
}
