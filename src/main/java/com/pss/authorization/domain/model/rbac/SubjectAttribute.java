package com.pss.authorization.domain.model.rbac;

import com.pss.authorization.domain.model.common.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Dynamic attribute assigned to a subject for ABAC evaluation.
 * Attributes can have temporal validity (valid_from, valid_until).
 */
@Entity
@Table(name = "subject_attributes", indexes = {
        @Index(name = "idx_subject_attr_lookup", columnList = "subject_id, attribute_name"),
        @Index(name = "idx_subject_attr_validity", columnList = "subject_id, valid_from, valid_until")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SubjectAttribute extends BaseEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "subject_id", nullable = false)
    private Subject subject;

    @Column(name = "attribute_name", nullable = false, length = 128)
    private String attributeName;

    @Column(name = "attribute_value", nullable = false, length = 2048)
    private String attributeValue;

    @Column(name = "value_type", nullable = false, length = 32)
    @Builder.Default
    private String valueType = "STRING"; // STRING, NUMBER, BOOLEAN, LIST, DATE

    @Column(name = "valid_from")
    private Instant validFrom;

    @Column(name = "valid_until")
    private Instant validUntil;

    @PrePersist
    public void prePersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
    }

    /**
     * Checks if this attribute is currently valid.
     */
    public boolean isValid() {
        Instant now = Instant.now();
        boolean afterStart = validFrom == null || !now.isBefore(validFrom);
        boolean beforeEnd = validUntil == null || now.isBefore(validUntil);
        return afterStart && beforeEnd;
    }
}
