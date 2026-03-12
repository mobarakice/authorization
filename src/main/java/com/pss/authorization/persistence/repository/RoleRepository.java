package com.pss.authorization.persistence.repository;

import com.pss.authorization.domain.model.rbac.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Repository for Role entity with optimized queries for performance.
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByTenantIdAndName(String tenantId, String name);

    List<Role> findByTenantIdAndActiveTrue(String tenantId);

    @Query("SELECT r FROM Role r WHERE r.tenantId = :tenantId AND r.systemRole = true AND r.active = true")
    List<Role> findSystemRoles(@Param("tenantId") String tenantId);

    @Query("SELECT r FROM Role r LEFT JOIN FETCH r.permissions WHERE r.id IN :roleIds")
    List<Role> findByIdsWithPermissions(@Param("roleIds") Set<UUID> roleIds);

    @Query("SELECT r FROM Role r LEFT JOIN FETCH r.permissions LEFT JOIN FETCH r.parentRoles WHERE r.id = :id")
    Optional<Role> findByIdWithPermissionsAndHierarchy(@Param("id") UUID id);

    @Query("""
            SELECT DISTINCT r FROM Role r
            LEFT JOIN FETCH r.permissions p
            LEFT JOIN FETCH p.resource
            WHERE r.tenantId = :tenantId AND r.active = true
            """)
    List<Role> findActiveRolesWithPermissions(@Param("tenantId") String tenantId);

    @Query("""
            SELECT r FROM Role r
            WHERE r.tenantId = :tenantId
            AND r.hierarchyPath LIKE CONCAT(:parentPath, '%')
            AND r.active = true
            """)
    List<Role> findDescendantRoles(@Param("tenantId") String tenantId, @Param("parentPath") String parentPath);
}
