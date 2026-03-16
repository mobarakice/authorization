package com.pss.authorization.domain.model.rbac;

import com.pss.authorization.domain.model.common.TenantAwareEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

/**
 * Represents a role that groups permissions together.
 * Roles support hierarchical inheritance through parent-child relationships.
 */
@Entity
@Table(name = "roles", indexes = {
        @Index(name = "idx_roles_tenant_name", columnList = "tenant_id, name", unique = true),
        @Index(name = "idx_roles_system", columnList = "system_role")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role extends TenantAwareEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "entity_seq")
    @SequenceGenerator(name = "entity_seq", sequenceName = "entity_sequence", allocationSize = 50)
    private Long id;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "description", length = 512)
    private String description;

    /**
     * System roles cannot be deleted or modified by regular users.
     */
    @Column(name = "system_role", nullable = false)
    @Builder.Default
    private boolean systemRole = false;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    /**
     * Materialized path for efficient hierarchy traversal.
     * Example: "/root/admin/super_admin/" enables LIKE queries for descendants.
     */
    @Column(name = "hierarchy_path", length = 1024)
    private String hierarchyPath;

    /**
     * Depth in the role hierarchy (0 for root roles).
     */
    @Column(name = "hierarchy_depth", nullable = false)
    @Builder.Default
    private int hierarchyDepth = 0;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "role_permissions", joinColumns = @JoinColumn(name = "role_id"), inverseJoinColumns = @JoinColumn(name = "permission_id"))
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>();

    /**
     * Parent roles from which this role inherits permissions.
     */
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "role_hierarchy", joinColumns = @JoinColumn(name = "child_role_id"), inverseJoinColumns = @JoinColumn(name = "parent_role_id"))
    @Builder.Default
    private Set<Role> parentRoles = new HashSet<>();

    /**
     * Child roles that inherit from this role.
     */
    @ManyToMany(mappedBy = "parentRoles")
    @Builder.Default
    private Set<Role> childRoles = new HashSet<>();

    @ManyToMany(mappedBy = "roles")
    @Builder.Default
    private Set<Subject> subjects = new HashSet<>();

    /**
     * Collects all permissions including inherited ones from parent roles.
     */
    public Set<Permission> getAllPermissions() {
        Set<Permission> allPermissions = new HashSet<>(permissions);
        for (Role parent : parentRoles) {
            allPermissions.addAll(parent.getAllPermissions());
        }
        return allPermissions;
    }
}
