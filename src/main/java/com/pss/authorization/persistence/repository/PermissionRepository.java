package com.pss.authorization.persistence.repository;

import com.pss.authorization.domain.model.rbac.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for Permission entity.
 */
@Repository
public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    Optional<Permission> findByTenantIdAndName(String tenantId, String name);

    List<Permission> findByTenantIdAndActiveTrue(String tenantId);

    @Query("SELECT p FROM Permission p JOIN FETCH p.resource WHERE p.tenantId = :tenantId AND p.active = true")
    List<Permission> findActiveWithResources(@Param("tenantId") String tenantId);

    @Query("""
            SELECT p FROM Permission p
            JOIN FETCH p.resource r
            WHERE p.tenantId = :tenantId
            AND r.name = :resourceName
            AND p.action = :action
            AND p.active = true
            """)
    Optional<Permission> findByResourceAndAction(
            @Param("tenantId") String tenantId,
            @Param("resourceName") String resourceName,
            @Param("action") String action);

    @Query("SELECT MAX(p.bitIndex) FROM Permission p WHERE p.tenantId = :tenantId")
    Optional<Integer> findMaxBitIndex(@Param("tenantId") String tenantId);

    @Query("""
            SELECT p FROM Permission p
            JOIN FETCH p.resource
            WHERE p.tenantId = :tenantId
            AND p.active = true
            ORDER BY p.bitIndex
            """)
    List<Permission> findAllForBitmapBuilding(@Param("tenantId") String tenantId);
}
