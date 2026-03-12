package com.pss.authorization.domain.model.rbac;

import com.pss.authorization.domain.model.common.TenantAwareEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Represents a permission granting access to perform an action on a resource.
 * Permissions are assigned to roles, not directly to users.
 */
@Entity
@Table(name = "permissions", indexes = {
        @Index(name = "idx_permissions_tenant_name", columnList = "tenant_id, name", unique = true),
        @Index(name = "idx_permissions_resource_action", columnList = "resource_id, action")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Permission extends TenantAwareEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "action", nullable = false, length = 32)
    private String action; // CREATE, READ, UPDATE, DELETE, EXECUTE, etc.

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "resource_id", nullable = false)
    private Resource resource;

    @Column(name = "description", length = 512)
    private String description;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    /**
     * Bit index for permission bitmap optimization.
     * Each permission gets a unique index for O(1) lookup.
     */
    @Column(name = "bit_index", nullable = false)
    private int bitIndex;

    @ManyToMany(mappedBy = "permissions")
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    @PrePersist
    public void prePersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
    }

    /**
     * Returns the fully qualified permission name: resource:action
     */
    public String getFullName() {
        return resource.getName() + ":" + action;
    }
}
