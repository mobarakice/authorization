package com.pss.authorization.api.rest;

import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.service.AuthorizationService;
import io.micrometer.core.annotation.Timed;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST API Controller for authorization checks.
 */
@RestController
@RequestMapping("/api/v1/authorize")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authorization", description = "Authorization check endpoints - Target latency: < 5ms")
public class AuthorizationController {

        private final AuthorizationService authorizationService;

        @Operation(summary = "Authorize a request", description = "Evaluates an authorization request using RBAC, ABAC, or Hybrid mode. Target latency: < 5ms")
        @ApiResponses({
                        @ApiResponse(responseCode = "200", description = "Authorization decision returned", content = @Content(schema = @Schema(implementation = AuthorizationResponse.class))),
                        @ApiResponse(responseCode = "400", description = "Invalid request")
        })
        @PostMapping
        @Timed(value = "authorization.check", description = "Authorization check latency")
        public ResponseEntity<AuthorizationResponse> authorize(
                        @Valid @RequestBody AuthorizationRequest request) {
                return ResponseEntity.ok(authorizationService.authorize(request));
        }

        @Operation(summary = "Batch authorization check", description = "Evaluates multiple authorization requests in a single call. More efficient for checking multiple permissions.")
        @ApiResponses({
                        @ApiResponse(responseCode = "200", description = "Authorization decisions returned"),
                        @ApiResponse(responseCode = "400", description = "Invalid request")
        })
        @PostMapping("/batch")
        @Timed(value = "authorization.batch", description = "Batch authorization check latency")
        public ResponseEntity<List<AuthorizationResponse>> authorizeBatch(
                        @Valid @RequestBody List<AuthorizationRequest> requests) {
                return ResponseEntity.ok(authorizationService.authorizeBatch(requests));
        }

        @Operation(summary = "Simple permission check", description = "Quick check if a subject has permission to perform an action on a resource")
        @ApiResponses({
                        @ApiResponse(responseCode = "200", description = "Permission check result"),
                        @ApiResponse(responseCode = "400", description = "Missing required parameters")
        })
        @GetMapping("/check")
        @Timed(value = "authorization.simple.check", description = "Simple authorization check latency")
        public ResponseEntity<Map<String, Object>> checkPermission(
                        @Parameter(description = "Tenant identifier", required = true) @RequestHeader("X-Tenant-ID") String tenantId,
                        @Parameter(description = "Subject/User identifier", required = true) @RequestHeader("X-Subject-ID") String subjectId,
                        @Parameter(description = "Resource name (e.g., 'orders', 'users')", required = true) @RequestParam String resource,
                        @Parameter(description = "Action (e.g., 'READ', 'WRITE', 'DELETE')", required = true) @RequestParam String action) {

        var request = AuthorizationRequest.builder()
                                .tenantId(tenantId)
                                .externalSubjectId(subjectId)
                                .resource(resource)
                                .action(action)
                                .build();

        var response = authorizationService.authorize(request);

                return ResponseEntity.ok(Map.of(
                                "permitted", response.isPermitted(),
                                "decision", response.decision(),
                                "evaluationTimeMs", response.evaluationTimeMs()));
        }

        @Operation(summary = "Debug authorization", description = "Authorization check with verbose evaluation details showing engine decisions")
        @PostMapping("/debug")
        public ResponseEntity<AuthorizationResponse> authorizeDebug(
                        @Valid @RequestBody AuthorizationRequest request) {
        var verboseRequest = request.toBuilder().verbose(true).build();
                return ResponseEntity.ok(authorizationService.authorize(verboseRequest));
        }
}
