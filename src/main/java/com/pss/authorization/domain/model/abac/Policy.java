package com.pss.authorization.domain.model.abac;

import com.pss.authorization.domain.model.common.TenantAwareEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * ABAC Policy that defines access control rules based on attributes.
 * Policies contain rules that are evaluated against request attributes.
 */
@Entity
@Table(name = "policies", indexes = {
        @Index(name = "idx_policies_tenant_name", columnList = "tenant_id, name", unique = true),
        @Index(name = "idx_policies_target", columnList = "tenant_id, target_resource, target_action"),
        @Index(name = "idx_policies_priority", columnList = "tenant_id, priority")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Policy extends TenantAwareEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "description", length = 1024)
    private String description;

    /**
     * Target resource pattern (supports wildcards).
     * Examples: "orders", "orders:*", "*"
     */
    @Column(name = "target_resource", nullable = false, length = 256)
    private String targetResource;

    /**
     * Target action pattern (supports wildcards).
     * Examples: "READ", "WRITE", "*"
     */
    @Column(name = "target_action", nullable = false, length = 64)
    @Builder.Default
    private String targetAction = "*";

    @Enumerated(EnumType.STRING)
    @Column(name = "effect", nullable = false, length = 16)
    private PolicyEffect effect;

    /**
     * Lower priority number = higher precedence.
     * Used when multiple policies apply to the same request.
     */
    @Column(name = "priority", nullable = false)
    @Builder.Default
    private int priority = 100;

    @Enumerated(EnumType.STRING)
    @Column(name = "combining_algorithm", nullable = false, length = 32)
    @Builder.Default
    private CombiningAlgorithm combiningAlgorithm = CombiningAlgorithm.DENY_OVERRIDES;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    @OneToMany(mappedBy = "policy", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("orderIndex ASC")
    @Builder.Default
    private Set<PolicyRule> rules = new LinkedHashSet<>();

    @Version
    @Column(name = "version")
    private Long version;

    @PrePersist
    public void prePersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
    }

    /**
     * Checks if this policy targets the given resource and action.
     */
    public boolean matchesTarget(String resource, String action) {
        boolean resourceMatch = "*".equals(targetResource)
                || targetResource.equals(resource)
                || (targetResource.endsWith(":*") && resource.startsWith(targetResource.replace(":*", ":")));

        boolean actionMatch = "*".equals(targetAction) || targetAction.equals(action);

        return resourceMatch && actionMatch;
    }
}
