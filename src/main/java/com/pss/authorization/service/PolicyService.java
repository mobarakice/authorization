package com.pss.authorization.service;

import com.pss.authorization.cache.TwoLevelCacheManager;
import com.pss.authorization.domain.model.abac.Policy;
import com.pss.authorization.persistence.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PolicyService {

    private final PolicyRepository policyRepository;
    private final TwoLevelCacheManager cacheManager;

    @Transactional(readOnly = true)
    public List<Policy> listPolicies(String tenantId) {
        return policyRepository.findByTenantIdAndActiveTrue(tenantId);
    }

    @Transactional(readOnly = true)
    public Optional<Policy> getPolicy(Long id, String tenantId) {
        return policyRepository.findByIdWithRulesAndConditions(id)
                .filter(p -> p.getTenantId().equals(tenantId));
    }

    @Transactional
    public Policy createPolicy(String tenantId, Policy policy) {
        policy.setTenantId(tenantId);
        Policy saved = policyRepository.save(policy);
        cacheManager.invalidatePolicies(tenantId);
        return saved;
    }

    @Transactional
    public Optional<Policy> updatePolicy(String tenantId, Long id, Policy incoming) {
        return policyRepository.findById(id)
                .filter(p -> p.getTenantId().equals(tenantId))
                .map(existing -> {
                    existing.setName(incoming.getName());
                    existing.setDescription(incoming.getDescription());
                    existing.setTargetResource(incoming.getTargetResource());
                    existing.setTargetAction(incoming.getTargetAction());
                    existing.setEffect(incoming.getEffect());
                    existing.setPriority(incoming.getPriority());
                    existing.setCombiningAlgorithm(incoming.getCombiningAlgorithm());
                    existing.setActive(incoming.isActive());
                    Policy saved = policyRepository.save(existing);
                    cacheManager.invalidatePolicies(tenantId);
                    return saved;
                });
    }

    @Transactional
    public boolean deletePolicy(String tenantId, Long id) {
        return policyRepository.findById(id)
                .filter(p -> p.getTenantId().equals(tenantId))
                .map(policy -> {
                    policy.setActive(false);
                    policyRepository.save(policy);
                    cacheManager.invalidatePolicies(tenantId);
                    return true;
                })
                .orElse(false);
    }
}
