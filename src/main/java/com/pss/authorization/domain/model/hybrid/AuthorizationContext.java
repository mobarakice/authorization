package com.pss.authorization.domain.model.hybrid;

import com.pss.authorization.domain.model.common.TenantAwareEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Defines the authorization context for a specific resource or scope.
 * Contexts determine which authorization mode and strategy to apply.
 */
@Entity
@Table(name = "authorization_contexts", indexes = {
        @Index(name = "idx_auth_ctx_tenant_name", columnList = "tenant_id, name", unique = true),
        @Index(name = "idx_auth_ctx_resource", columnList = "tenant_id, resource_pattern")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthorizationContext extends TenantAwareEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "description", length = 512)
    private String description;

    /**
     * Resource pattern this context applies to.
     * Supports wildcards: "orders:*", "*"
     */
    @Column(name = "resource_pattern", nullable = false, length = 256)
    private String resourcePattern;

    @Enumerated(EnumType.STRING)
    @Column(name = "mode", nullable = false, length = 16)
    private AuthorizationMode mode;

    @Enumerated(EnumType.STRING)
    @Column(name = "combining_strategy", length = 32)
    private CombiningStrategy combiningStrategy;

    /**
     * Priority for context matching (lower = higher priority).
     */
    @Column(name = "priority", nullable = false)
    @Builder.Default
    private int priority = 100;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    @OneToMany(mappedBy = "context", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("priority ASC")
    @Builder.Default
    private List<ContextRule> rules = new ArrayList<>();

    @PrePersist
    public void prePersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
    }

    /**
     * Checks if this context matches the given resource.
     */
    public boolean matchesResource(String resource) {
        if ("*".equals(resourcePattern)) {
            return true;
        }
        if (resourcePattern.endsWith(":*")) {
            String prefix = resourcePattern.replace(":*", ":");
            return resource.startsWith(prefix);
        }
        return resourcePattern.equals(resource);
    }
}
