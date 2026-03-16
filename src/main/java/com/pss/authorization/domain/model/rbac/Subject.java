package com.pss.authorization.domain.model.rbac;

import com.pss.authorization.domain.model.common.TenantAwareEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * Represents a subject (user/service account) that can be authorized.
 * Subjects are identified by external_id from the identity provider.
 */
@Entity
@Table(name = "subjects", indexes = {
        @Index(name = "idx_subjects_external_id", columnList = "tenant_id, external_id", unique = true),
        @Index(name = "idx_subjects_active", columnList = "tenant_id, active")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Subject extends TenantAwareEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "entity_seq")
    @SequenceGenerator(name = "entity_seq", sequenceName = "entity_sequence", allocationSize = 50)
    private Long id;

    /**
     * External identifier from identity provider (e.g., sub claim from JWT).
     */
    @Column(name = "external_id", nullable = false, length = 256)
    private String externalId;

    /**
     * Type of subject: USER, SERVICE_ACCOUNT, API_KEY
     */
    @Column(name = "subject_type", nullable = false, length = 32)
    @Builder.Default
    private String subjectType = "USER";

    @Column(name = "display_name", length = 256)
    private String displayName;

    @Column(name = "email", length = 320)
    private String email;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    @Column(name = "last_activity_at")
    private Instant lastActivityAt;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "subject_roles", joinColumns = @JoinColumn(name = "subject_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    /**
     * Dynamically assigned attributes for ABAC evaluation.
     */
    @OneToMany(mappedBy = "subject", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<SubjectAttribute> attributes = new HashSet<>();

    /**
     * Collects all permissions from all assigned roles (including inherited).
     */
    public Set<Permission> getAllPermissions() {
        Set<Permission> allPermissions = new HashSet<>();
        for (Role role : roles) {
            allPermissions.addAll(role.getAllPermissions());
        }
        return allPermissions;
    }
}
