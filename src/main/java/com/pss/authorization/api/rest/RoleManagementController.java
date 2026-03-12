package com.pss.authorization.api.rest;

import com.pss.authorization.domain.model.rbac.Role;
import com.pss.authorization.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * REST API for Role management.
 */
@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
@Tag(name = "Role Management", description = "CRUD operations for roles")
public class RoleManagementController {

    private final RoleService roleService;

    @Operation(summary = "List all roles", description = "Get all active roles for the tenant")
    @GetMapping
    public ResponseEntity<List<Role>> listRoles(
            @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId) {
        return ResponseEntity.ok(roleService.listRoles(tenantId));
    }

    @Operation(summary = "Get role by ID", description = "Get a specific role with its permissions and hierarchy")
    @GetMapping("/{id}")
    public ResponseEntity<Role> getRole(
            @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId,
            @Parameter(description = "Role UUID") @PathVariable UUID id) {
        return roleService.getRole(id, tenantId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(summary = "Create role", description = "Create a new role")
    @PostMapping
    public ResponseEntity<Role> createRole(
            @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId,
            @Valid @RequestBody Role role) {
        return ResponseEntity.status(HttpStatus.CREATED).body(roleService.createRole(tenantId, role));
    }

    @Operation(summary = "Update role", description = "Update an existing role")
    @PutMapping("/{id}")
    public ResponseEntity<Role> updateRole(
            @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId,
            @Parameter(description = "Role UUID") @PathVariable UUID id,
            @Valid @RequestBody Role role) {
        return roleService.updateRole(tenantId, id, role)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(summary = "Delete role", description = "Soft-delete a role (system roles cannot be deleted)")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteRole(
            @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId,
            @Parameter(description = "Role UUID") @PathVariable UUID id) {
        return roleService.deleteRole(tenantId, id)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }
}
