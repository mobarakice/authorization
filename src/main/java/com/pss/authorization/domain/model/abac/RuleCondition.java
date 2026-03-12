package com.pss.authorization.domain.model.abac;

import com.pss.authorization.domain.model.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

/**
 * A condition within a policy rule.
 * Conditions compare an attribute value against an expected value using an
 * operator.
 */
@Entity
@Table(name = "rule_conditions", indexes = {
        @Index(name = "idx_rule_conditions_rule", columnList = "rule_id, order_index")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RuleCondition extends BaseEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "rule_id", nullable = false)
    private PolicyRule rule;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "attribute_id", nullable = false)
    private AttributeDefinition attribute;

    @Enumerated(EnumType.STRING)
    @Column(name = "operator", nullable = false, length = 32)
    private ConditionOperator operator;

    /**
     * Expected value to compare against.
     * For complex types (lists), use JSON format.
     */
    @Column(name = "expected_value", length = 2048)
    private String expectedValue;

    /**
     * Optional second value for BETWEEN operator.
     */
    @Column(name = "expected_value_2", length = 2048)
    private String expectedValue2;

    /**
     * If true, negate the condition result.
     */
    @Column(name = "negate", nullable = false)
    @Builder.Default
    private boolean negate = false;

    /**
     * Order in which this condition is evaluated within the rule.
     */
    @Column(name = "order_index", nullable = false)
    @Builder.Default
    private int orderIndex = 0;

    @PrePersist
    public void prePersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
    }
}
