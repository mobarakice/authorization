package com.pss.authorization.service;

import com.pss.authorization.cache.TwoLevelCacheManager;
import com.pss.authorization.domain.model.rbac.Role;
import com.pss.authorization.persistence.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;
    private final TwoLevelCacheManager cacheManager;

    @Transactional(readOnly = true)
    public List<Role> listRoles(String tenantId) {
        return roleRepository.findByTenantIdAndActiveTrue(tenantId);
    }

    @Transactional(readOnly = true)
    public Optional<Role> getRole(UUID id, String tenantId) {
        return roleRepository.findByIdWithPermissionsAndHierarchy(id)
                .filter(r -> r.getTenantId().equals(tenantId));
    }

    @Transactional
    public Role createRole(String tenantId, Role role) {
        role.setTenantId(tenantId);
        return roleRepository.save(role);
    }

    @Transactional
    public Optional<Role> updateRole(String tenantId, UUID id, Role incoming) {
        return roleRepository.findById(id)
                .filter(r -> r.getTenantId().equals(tenantId))
                .map(existing -> {
                    existing.setName(incoming.getName());
                    existing.setDescription(incoming.getDescription());
                    existing.setActive(incoming.isActive());
                    Role saved = roleRepository.save(existing);
                    cacheManager.invalidateTenant(tenantId);
                    return saved;
                });
    }

    @Transactional
    public boolean deleteRole(String tenantId, UUID id) {
        return roleRepository.findById(id)
                .filter(r -> r.getTenantId().equals(tenantId))
                .filter(r -> !r.isSystemRole())
                .map(role -> {
                    role.setActive(false);
                    roleRepository.save(role);
                    cacheManager.invalidateTenant(tenantId);
                    return true;
                })
                .orElse(false);
    }
}
