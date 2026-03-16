package com.pss.authorization.persistence.repository;

import com.pss.authorization.domain.model.abac.Policy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for ABAC Policy entity.
 */
@Repository
public interface PolicyRepository extends JpaRepository<Policy, Long> {

    Optional<Policy> findByTenantIdAndName(String tenantId, String name);

    List<Policy> findByTenantIdAndActiveTrue(String tenantId);

    @Query("""
            SELECT DISTINCT p FROM Policy p
            LEFT JOIN FETCH p.rules r
            LEFT JOIN FETCH r.conditions c
            LEFT JOIN FETCH c.attribute
            WHERE p.tenantId = :tenantId
            AND p.active = true
            ORDER BY p.priority ASC
            """)
    List<Policy> findActivePoliciesWithRules(@Param("tenantId") String tenantId);

    @Query("""
            SELECT DISTINCT p FROM Policy p
            LEFT JOIN FETCH p.rules r
            LEFT JOIN FETCH r.conditions c
            LEFT JOIN FETCH c.attribute
            WHERE p.tenantId = :tenantId
            AND p.active = true
            AND (p.targetResource = '*'
                 OR p.targetResource = :resource
                 OR (p.targetResource LIKE '%:*' AND :resource LIKE CONCAT(SUBSTRING(p.targetResource, 1, LENGTH(p.targetResource) - 1), '%')))
            AND (p.targetAction = '*' OR p.targetAction = :action)
            ORDER BY p.priority ASC
            """)
    List<Policy> findApplicablePolicies(
            @Param("tenantId") String tenantId,
            @Param("resource") String resource,
            @Param("action") String action);

    @Query("""
            SELECT p FROM Policy p
            LEFT JOIN FETCH p.rules r
            LEFT JOIN FETCH r.conditions
            WHERE p.id = :id
            """)
    Optional<Policy> findByIdWithRulesAndConditions(@Param("id") Long id);
}
