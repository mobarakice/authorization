package com.pss.authorization.domain.model.hybrid;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.pss.authorization.domain.model.abac.Policy;
import com.pss.authorization.domain.model.common.BaseEntity;
import com.pss.authorization.domain.model.rbac.Role;
import jakarta.persistence.*;
import lombok.*;


/**
 * A rule within an authorization context.
 * Links the context to specific roles (RBAC) or policies (ABAC).
 */
@Entity
@Table(name = "context_rules", indexes = {
        @Index(name = "idx_context_rules_ctx", columnList = "context_id, priority")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ContextRule extends BaseEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "entity_seq")
    @SequenceGenerator(name = "entity_seq", sequenceName = "entity_sequence", allocationSize = 50)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "context_id", nullable = false)
    @JsonIgnore
    private AuthorizationContext context;

    /**
     * Type of rule: RBAC or ABAC
     */
    @Column(name = "rule_type", nullable = false, length = 16)
    private String ruleType;

    /**
     * Reference to a role (for RBAC rules).
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id")
    private Role role;

    /**
     * Reference to a policy (for ABAC rules).
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id")
    private Policy policy;

    /**
     * Whether this rule is required for authorization.
     */
    @Column(name = "required", nullable = false)
    @Builder.Default
    private boolean required = true;

    /**
     * Evaluation priority within the context.
     */
    @Column(name = "priority", nullable = false)
    @Builder.Default
    private int priority = 100;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    public boolean isRbacRule() {
        return "RBAC".equals(ruleType);
    }

    public boolean isAbacRule() {
        return "ABAC".equals(ruleType);
    }
}
