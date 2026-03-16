package com.pss.authorization.domain.model.rbac;

import com.pss.authorization.domain.model.common.TenantAwareEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

/**
 * Represents a resource that can be protected by authorization rules.
 * Resources are the targets of permissions (e.g., "orders", "users",
 * "reports").
 */
@Entity
@Table(name = "resources", indexes = {
        @Index(name = "idx_resources_tenant_name", columnList = "tenant_id, name", unique = true),
        @Index(name = "idx_resources_type", columnList = "type")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Resource extends TenantAwareEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "entity_seq")
    @SequenceGenerator(name = "entity_seq", sequenceName = "entity_sequence", allocationSize = 50)
    private Long id;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "type", nullable = false, length = 64)
    private String type;

    @Column(name = "description", length = 512)
    private String description;

    @Column(name = "metadata", columnDefinition = "jsonb")
    private String metadata;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    @OneToMany(mappedBy = "resource", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>();
}
