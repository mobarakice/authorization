package com.pss.authorization.persistence.repository;

import com.pss.authorization.domain.model.rbac.Subject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Repository for Subject entity.
 */
@Repository
public interface SubjectRepository extends JpaRepository<Subject, UUID> {

    Optional<Subject> findByTenantIdAndExternalId(String tenantId, String externalId);

    @Query("""
            SELECT s FROM Subject s
            LEFT JOIN FETCH s.roles r
            LEFT JOIN FETCH r.permissions p
            LEFT JOIN FETCH p.resource
            WHERE s.tenantId = :tenantId
            AND s.externalId = :externalId
            AND s.active = true
            """)
    Optional<Subject> findByExternalIdWithRolesAndPermissions(
            @Param("tenantId") String tenantId,
            @Param("externalId") String externalId);

    @Query("""
            SELECT s FROM Subject s
            LEFT JOIN FETCH s.attributes
            WHERE s.tenantId = :tenantId
            AND s.externalId = :externalId
            AND s.active = true
            """)
    Optional<Subject> findByExternalIdWithAttributes(
            @Param("tenantId") String tenantId,
            @Param("externalId") String externalId);

    @Query("""
            SELECT s FROM Subject s
            LEFT JOIN FETCH s.roles r
            LEFT JOIN FETCH r.permissions
            LEFT JOIN FETCH s.attributes
            WHERE s.id = :id AND s.active = true
            """)
    Optional<Subject> findByIdFullyLoaded(@Param("id") UUID id);
}
