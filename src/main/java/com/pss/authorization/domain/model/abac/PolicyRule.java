package com.pss.authorization.domain.model.abac;

import com.pss.authorization.domain.model.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * A rule within an ABAC policy.
 * Rules contain conditions that must be satisfied for the rule to apply.
 */
@Entity
@Table(name = "policy_rules", indexes = {
        @Index(name = "idx_policy_rules_policy", columnList = "policy_id, order_index")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PolicyRule extends BaseEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "description", length = 512)
    private String description;

    /**
     * Order in which this rule is evaluated within the policy.
     */
    @Column(name = "order_index", nullable = false)
    @Builder.Default
    private int orderIndex = 0;

    /**
     * How conditions within this rule are combined.
     * AND = all conditions must match
     * OR = any condition must match
     */
    @Column(name = "condition_logic", nullable = false, length = 8)
    @Builder.Default
    private String conditionLogic = "AND";

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    @OneToMany(mappedBy = "rule", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("orderIndex ASC")
    @Builder.Default
    private Set<RuleCondition> conditions = new LinkedHashSet<>();

    @PrePersist
    public void prePersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
    }

    /**
     * Adds a condition to this rule.
     */
    public void addCondition(RuleCondition condition) {
        conditions.add(condition);
        condition.setRule(this);
        condition.setOrderIndex(conditions.size() - 1);
    }
}
