package com.pss.authorization.api.rest;

import com.pss.authorization.domain.model.abac.Policy;
import com.pss.authorization.service.PolicyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST API for ABAC Policy management.
 */
@RestController
@RequestMapping("/api/v1/policies")
@RequiredArgsConstructor
@Tag(name = "Policy Management", description = "CRUD operations for ABAC policies")
public class PolicyManagementController {

    private final PolicyService policyService;

    @Operation(summary = "List all policies", description = "Get all active ABAC policies for the tenant")
    @GetMapping
    public ResponseEntity<List<Policy>> listPolicies(
            @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId) {
        return ResponseEntity.ok(policyService.listPolicies(tenantId));
    }

    @Operation(summary = "Get policy by ID", description = "Get a specific policy with its rules and conditions")
    @GetMapping("/{id}")
    public ResponseEntity<Policy> getPolicy(
            @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId,
            @Parameter(description = "Policy Long") @PathVariable Long id) {
        return policyService.getPolicy(id, tenantId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(summary = "Create policy", description = "Create a new ABAC policy")
    @PostMapping
    public ResponseEntity<Policy> createPolicy(
            @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId,
            @Valid @RequestBody Policy policy) {
        return ResponseEntity.status(HttpStatus.CREATED).body(policyService.createPolicy(tenantId, policy));
    }

    @Operation(summary = "Update policy", description = "Update an existing ABAC policy")
    @PutMapping("/{id}")
    public ResponseEntity<Policy> updatePolicy(
            @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId,
            @Parameter(description = "Policy Long") @PathVariable Long id,
            @Valid @RequestBody Policy policy) {
        return policyService.updatePolicy(tenantId, id, policy)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(summary = "Delete policy", description = "Soft-delete an ABAC policy")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePolicy(
            @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId,
            @Parameter(description = "Policy Long") @PathVariable Long id) {
        return policyService.deletePolicy(tenantId, id)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }
}
