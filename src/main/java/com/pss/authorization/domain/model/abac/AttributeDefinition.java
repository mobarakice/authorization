package com.pss.authorization.domain.model.abac;

import com.pss.authorization.domain.model.common.TenantAwareEntity;
import jakarta.persistence.*;
import lombok.*;


/**
 * Defines an attribute that can be used in ABAC policies.
 * Attributes are referenced by conditions to evaluate access requests.
 */
@Entity
@Table(name = "attribute_definitions", indexes = {
        @Index(name = "idx_attr_def_tenant_name", columnList = "tenant_id, name", unique = true),
        @Index(name = "idx_attr_def_category", columnList = "category")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AttributeDefinition extends TenantAwareEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "entity_seq")
    @SequenceGenerator(name = "entity_seq", sequenceName = "entity_sequence", allocationSize = 50)
    private Long id;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "display_name", length = 256)
    private String displayName;

    @Column(name = "description", length = 512)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "category", nullable = false, length = 32)
    private AttributeCategory category;

    @Enumerated(EnumType.STRING)
    @Column(name = "data_type", nullable = false, length = 32)
    private AttributeDataType dataType;

    /**
     * Source of the attribute value during evaluation.
     * JWT - from JWT claims
     * HEADER - from HTTP headers
     * DATABASE - from subject/resource attributes in DB
     * CONTEXT - from request context
     * ENVIRONMENT - from system (time, etc.)
     */
    @Column(name = "source", nullable = false, length = 32)
    private String source;

    /**
     * Path to extract the attribute from its source.
     * For JWT: claim path like "user.department"
     * For HEADER: header name like "X-Client-IP"
     */
    @Column(name = "source_path", length = 256)
    private String sourcePath;

    @Column(name = "required", nullable = false)
    @Builder.Default
    private boolean required = false;

    @Column(name = "default_value", length = 1024)
    private String defaultValue;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;
}
