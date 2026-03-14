package com.pss.authorization.domain.engine;

import com.pss.authorization.cache.TwoLevelCacheManager;
import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.dto.AuthorizationResponse.Decision;
import com.pss.authorization.domain.dto.PermissionBitmap;
import com.pss.authorization.domain.model.rbac.Permission;
import com.pss.authorization.domain.model.rbac.Role;
import com.pss.authorization.domain.model.rbac.Subject;
import com.pss.authorization.persistence.repository.PermissionRepository;
import com.pss.authorization.persistence.repository.SubjectRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RbacEngineTest {

        static final String TENANT = "pss-test";
        static final String EXTERNAL_ID = "user-abc";
        static final String RESOURCE = "flight";
        static final String ACTION = "READ";
        static final int FLIGHT_READ_BIT = 0;

        @Mock
        TwoLevelCacheManager cacheManager;
        @Mock
        SubjectRepository subjectRepository;
        @Mock
        PermissionRepository permissionRepository;

        @InjectMocks
        RbacEngine rbacEngine;

        private AuthorizationRequest request;
        private UUID subjectCacheKey;

        @BeforeEach
        void setUp() {
                request = AuthorizationRequest.builder()
                                .tenantId(TENANT)
                                .externalSubjectId(EXTERNAL_ID)
                                .resource(RESOURCE)
                                .action(ACTION)
                                .build();

                subjectCacheKey = UUID.nameUUIDFromBytes(
                                (TENANT + ":" + EXTERNAL_ID).getBytes(StandardCharsets.UTF_8));
        }

        // --- canHandle ---

        @Test
        void canHandle_withTenantAndExternalId_returnsTrue() {
                assertThat(rbacEngine.canHandle(request)).isTrue();
        }

        @Test
        void canHandle_withSubjectId_returnsTrue() {
                var req = AuthorizationRequest.builder()
                                .tenantId(TENANT)
                                .subjectId("some-uuid")
                                .resource(RESOURCE)
                                .action(ACTION)
                                .build();
                assertThat(rbacEngine.canHandle(req)).isTrue();
        }

        @Test
        void canHandle_nullTenantId_returnsFalse() {
                var req = AuthorizationRequest.builder()
                                .externalSubjectId(EXTERNAL_ID)
                                .resource(RESOURCE)
                                .action(ACTION)
                                .build();
                assertThat(rbacEngine.canHandle(req)).isFalse();
        }

        @Test
        void canHandle_nullSubjectIds_returnsFalse() {
                var req = AuthorizationRequest.builder()
                                .tenantId(TENANT)
                                .resource(RESOURCE)
                                .action(ACTION)
                                .build();
                assertThat(rbacEngine.canHandle(req)).isFalse();
        }

        // --- evaluate: cache hit → PERMIT ---

        @Test
        void evaluate_cacheHitBitmapHasPermission_returnsPermit() {
                // L1 cache hit: bitmap with bit 0 set
                BitSet bits = new BitSet();
                bits.set(FLIGHT_READ_BIT);
                PermissionBitmap bitmap = PermissionBitmap.builder()
                                .subjectId(UUID.randomUUID())
                                .tenantId(TENANT)
                                .permissions(bits)
                                .build();

                when(cacheManager.getPermissionBitmap(TENANT, subjectCacheKey))
                                .thenReturn(Optional.of(bitmap));
                // bit index also cached
                when(cacheManager.getPermissionBitIndex(TENANT, RESOURCE, ACTION))
                                .thenReturn(Optional.of(FLIGHT_READ_BIT));

                AuthorizationResponse response = rbacEngine.evaluate(request);

                assertThat(response.getDecision()).isEqualTo(Decision.PERMIT);
                assertThat(response.isCached()).isTrue();
                // No DB calls when fully cached
                verifyNoInteractions(subjectRepository, permissionRepository);
        }

        @Test
        void evaluate_cacheHitBitmapMissingBit_returnsDeny() {
                // bitmap with NO bits set (subject has no permissions matching bit 0)
                PermissionBitmap bitmap = PermissionBitmap.builder()
                                .subjectId(UUID.randomUUID())
                                .tenantId(TENANT)
                                .permissions(new BitSet())
                                .build();

                when(cacheManager.getPermissionBitmap(TENANT, subjectCacheKey))
                                .thenReturn(Optional.of(bitmap));
                when(cacheManager.getPermissionBitIndex(TENANT, RESOURCE, ACTION))
                                .thenReturn(Optional.of(FLIGHT_READ_BIT));

                AuthorizationResponse response = rbacEngine.evaluate(request);

                assertThat(response.getDecision()).isEqualTo(Decision.DENY);
        }

        // --- evaluate: cache miss → load from DB ---

        @Test
        void evaluate_cacheMiss_subjectLoadedFromDB_returnsPermit() {
                // Cache misses
                when(cacheManager.getPermissionBitmap(TENANT, subjectCacheKey))
                                .thenReturn(Optional.empty());
                when(cacheManager.getPermissionBitIndex(TENANT, RESOURCE, ACTION))
                                .thenReturn(Optional.empty());

                // Build subject with role carrying permission at bit 0
                // (findByExternalIdWithRolesAndPermissions eagerly fetches roles + permissions)
                Permission perm = Permission.builder()
                                .id(UUID.randomUUID())
                                .bitIndex(FLIGHT_READ_BIT)
                                .build();
                UUID roleId = UUID.randomUUID();
                Role role = Role.builder()
                                .id(roleId)
                                .permissions(Set.of(perm))
                                .parentRoles(new HashSet<>())
                                .build();
                Subject subject = Subject.builder()
                                .id(UUID.randomUUID())
                                .externalId(EXTERNAL_ID)
                                .roles(Set.of(role))
                                .build();
                when(subjectRepository.findByExternalIdWithRolesAndPermissions(TENANT, EXTERNAL_ID))
                                .thenReturn(Optional.of(subject));

                // Permission definition in DB at bit 0
                Permission permDef = Permission.builder()
                                .id(UUID.randomUUID())
                                .bitIndex(FLIGHT_READ_BIT)
                                .build();
                when(permissionRepository.findByResourceAndAction(TENANT, RESOURCE, ACTION))
                                .thenReturn(Optional.of(permDef));

                AuthorizationResponse response = rbacEngine.evaluate(request);

                assertThat(response.getDecision()).isEqualTo(Decision.PERMIT);
                assertThat(response.isCached()).isFalse();
                verify(cacheManager).putPermissionBitmap(eq(TENANT), any(UUID.class), any(PermissionBitmap.class));
                verify(cacheManager).putPermissionBitIndex(TENANT, RESOURCE, ACTION, FLIGHT_READ_BIT);
        }

        @Test
        void evaluate_cacheMiss_permissionBitNotInRole_returnsDeny() {
                when(cacheManager.getPermissionBitmap(TENANT, subjectCacheKey))
                                .thenReturn(Optional.empty());
                when(cacheManager.getPermissionBitIndex(TENANT, RESOURCE, ACTION))
                                .thenReturn(Optional.empty());

                // Subject with role that has bit 5 (NOT bit 0 = flight:READ)
                Permission otherPerm = Permission.builder().id(UUID.randomUUID()).bitIndex(5).build();
                UUID roleId = UUID.randomUUID();
                Role role = Role.builder()
                                .id(roleId)
                                .permissions(Set.of(otherPerm))
                                .parentRoles(new HashSet<>())
                                .build();
                Subject subject = Subject.builder()
                                .id(UUID.randomUUID())
                                .externalId(EXTERNAL_ID)
                                .roles(Set.of(role))
                                .build();
                when(subjectRepository.findByExternalIdWithRolesAndPermissions(TENANT, EXTERNAL_ID))
                                .thenReturn(Optional.of(subject));

                // Permission exists at bit 0 but subject's bitmap doesn't have it
                Permission permDef = Permission.builder().id(UUID.randomUUID()).bitIndex(FLIGHT_READ_BIT).build();
                when(permissionRepository.findByResourceAndAction(TENANT, RESOURCE, ACTION))
                                .thenReturn(Optional.of(permDef));

                AuthorizationResponse response = rbacEngine.evaluate(request);

                assertThat(response.getDecision()).isEqualTo(Decision.DENY);
                assertThat(response.getReason()).contains(RESOURCE + ":" + ACTION);
        }

        // --- evaluate: subject not found ---

        @Test
        void evaluate_subjectNotFound_returnsDeny() {
                when(cacheManager.getPermissionBitmap(TENANT, subjectCacheKey))
                                .thenReturn(Optional.empty());
                when(subjectRepository.findByExternalIdWithRolesAndPermissions(TENANT, EXTERNAL_ID))
                                .thenReturn(Optional.empty());

                AuthorizationResponse response = rbacEngine.evaluate(request);

                assertThat(response.getDecision()).isEqualTo(Decision.DENY);
                assertThat(response.getReason()).containsIgnoringCase("subject not found");
        }

        // --- evaluate: permission not defined ---

        @Test
        void evaluate_permissionNotDefinedInDB_returnsNotApplicable() {
                when(cacheManager.getPermissionBitmap(TENANT, subjectCacheKey))
                                .thenReturn(Optional.empty());
                when(cacheManager.getPermissionBitIndex(TENANT, RESOURCE, ACTION))
                                .thenReturn(Optional.empty());

                UUID roleId = UUID.randomUUID();
                Role role = Role.builder().id(roleId).permissions(new HashSet<>()).parentRoles(new HashSet<>()).build();
                Subject subject = Subject.builder()
                                .id(UUID.randomUUID())
                                .externalId(EXTERNAL_ID)
                                .roles(Set.of(role))
                                .build();
                when(subjectRepository.findByExternalIdWithRolesAndPermissions(TENANT, EXTERNAL_ID))
                                .thenReturn(Optional.of(subject));

                // Permission not defined in DB
                when(permissionRepository.findByResourceAndAction(TENANT, RESOURCE, ACTION))
                                .thenReturn(Optional.empty());

                AuthorizationResponse response = rbacEngine.evaluate(request);

                assertThat(response.getDecision()).isEqualTo(Decision.NOT_APPLICABLE);
                assertThat(response.getReason()).contains("Permission not defined");
        }

        // --- evaluate: inherited permissions from parent role ---

        @Test
        void evaluate_inheritedPermissionFromParentRole_returnsPermit() {
                when(cacheManager.getPermissionBitmap(TENANT, subjectCacheKey))
                                .thenReturn(Optional.empty());
                when(cacheManager.getPermissionBitIndex(TENANT, RESOURCE, ACTION))
                                .thenReturn(Optional.empty());

                // Parent role has the permission; child role inherits it
                Permission perm = Permission.builder().id(UUID.randomUUID()).bitIndex(FLIGHT_READ_BIT).build();
                Role parentRole = Role.builder()
                                .id(UUID.randomUUID())
                                .permissions(Set.of(perm))
                                .parentRoles(new HashSet<>())
                                .build();
                UUID roleId = UUID.randomUUID();
                Role childRole = Role.builder()
                                .id(roleId)
                                .permissions(new HashSet<>())
                                .parentRoles(Set.of(parentRole))
                                .build();
                // Subject carries the child role (eagerly-loaded with parent hierarchy)
                Subject subject = Subject.builder()
                                .id(UUID.randomUUID())
                                .externalId(EXTERNAL_ID)
                                .roles(Set.of(childRole))
                                .build();
                when(subjectRepository.findByExternalIdWithRolesAndPermissions(TENANT, EXTERNAL_ID))
                                .thenReturn(Optional.of(subject));

                Permission permDef = Permission.builder().id(UUID.randomUUID()).bitIndex(FLIGHT_READ_BIT).build();
                when(permissionRepository.findByResourceAndAction(TENANT, RESOURCE, ACTION))
                                .thenReturn(Optional.of(permDef));

                AuthorizationResponse response = rbacEngine.evaluate(request);

                assertThat(response.getDecision()).isEqualTo(Decision.PERMIT);
        }

        // --- getEngineType ---

        @Test
        void getEngineType_returnsRBAC() {
                assertThat(rbacEngine.getEngineType()).isEqualTo("RBAC");
        }
}
