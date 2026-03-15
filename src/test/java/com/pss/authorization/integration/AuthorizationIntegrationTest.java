package com.pss.authorization.integration;

import com.pss.authorization.domain.dto.AuthorizationRequest;
import com.pss.authorization.domain.dto.AuthorizationResponse;
import com.pss.authorization.domain.dto.AuthorizationResponse.Decision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.web.client.RestTemplate;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests covering all 56 authorization scenarios from
 * example-usecase.md.
 *
 * Schema + seed data applied once before the test class via V1–V4 migration
 * scripts.
 * Tests are read-only (no DB writes) so the shared state is safe across all
 * cases.
 *
 * Users and roles (pss-example tenant):
 * mobarak → super-admin (all resources CRUD)
 * shamim → admin (flight+price+sales CRUD) + extra: price:BLOCK
 * mahtab → admin (flight+price+sales CRUD)
 * alamin → support-exec (flight:READ, pnl:READ) + extra: pnl:BLOCK
 * hasbullah → support-exec (flight:READ, pnl:READ) + extra: price:READ
 * nafi → booking-agent (flight:READ, pnr CRUD)
 * nahian → sale-exec (price+sales CRUD) + extra: pnr:READ
 * kiron → sale-exec (price+sales CRUD)
 */
@Sql(scripts = {
                "classpath:db/migration/V1__init_schema.sql",
                "classpath:db/migration/V2__seed_airline_data.sql",
                "classpath:db/migration/V3__seed_abac_hybrid_data.sql",
                "classpath:db/migration/V4__extra_permissions_abac.sql",
                "classpath:db/migration/V5__add_policy_bit_index.sql"
}, executionPhase = Sql.ExecutionPhase.BEFORE_TEST_CLASS)
class AuthorizationIntegrationTest extends AbstractIntegrationTest {

        static final String TENANT = "pss-example";

        @LocalServerPort
        int port;

        final RestTemplate restTemplate = new RestTemplate();

        private String url() {
                return "http://localhost:" + port + "/api/v1/authorize";
        }

        // -------------------------------------------------------------------------
        // 56 parameterized test cases
        // -------------------------------------------------------------------------

        static Stream<Arguments> authorizationScenarios() {
                return Stream.of(

                                // ── super-admin: Mobarak (all resources CRUD, no BLOCK) ────────────────
                                args("mobarak", "flight", "READ", Decision.PERMIT, "super-admin can read flight"),
                                args("mobarak", "flight", "UPDATE", Decision.PERMIT, "super-admin can update flight"),
                                args("mobarak", "flight", "DELETE", Decision.PERMIT, "super-admin can delete flight"),
                                args("mobarak", "pnr", "READ", Decision.PERMIT, "super-admin can read pnr"),
                                args("mobarak", "pnr", "DELETE", Decision.PERMIT, "super-admin can delete pnr"),
                                args("mobarak", "pnl", "READ", Decision.PERMIT, "super-admin can read pnl"),
                                args("mobarak", "pnl", "CREATE", Decision.PERMIT, "super-admin can create pnl"),
                                args("mobarak", "price", "READ", Decision.PERMIT, "super-admin can read price"),
                                args("mobarak", "price", "BLOCK", Decision.DENY,
                                                "super-admin has no price:BLOCK (extra perm only)"),
                                args("mobarak", "sales", "CREATE", Decision.PERMIT, "super-admin can create sales"),

                                // ── admin: Shamim (flight+price+sales CRUD) + extra: price:BLOCK ───────
                                args("shamim", "flight", "READ", Decision.PERMIT, "admin can read flight"),
                                args("shamim", "flight", "DELETE", Decision.PERMIT, "admin can delete flight"),
                                args("shamim", "price", "READ", Decision.PERMIT, "admin can read price (role)"),
                                args("shamim", "price", "BLOCK", Decision.PERMIT,
                                                "admin can block price (extra perm via ABAC)"),
                                args("shamim", "pnl", "BLOCK", Decision.DENY, "admin has no pnl:BLOCK"),
                                args("shamim", "pnr", "READ", Decision.DENY, "admin role has no pnr access"),
                                args("shamim", "pnl", "READ", Decision.DENY, "admin role has no pnl access"),

                                // ── admin: Mahtab (flight+price+sales CRUD, no extras) ────────────────
                                args("mahtab", "flight", "READ", Decision.PERMIT, "admin can read flight"),
                                args("mahtab", "flight", "DELETE", Decision.PERMIT, "admin can delete flight"),
                                args("mahtab", "price", "READ", Decision.PERMIT, "admin can read price"),
                                args("mahtab", "price", "BLOCK", Decision.DENY, "admin has no price:BLOCK"),
                                args("mahtab", "pnr", "READ", Decision.DENY, "admin has no pnr access"),
                                args("mahtab", "pnl", "READ", Decision.DENY, "admin has no pnl access"),
                                args("mahtab", "sales", "UPDATE", Decision.PERMIT, "admin can update sales"),

                                // ── support-executive: Alamin (flight:READ, pnl:READ) + extra: pnl:BLOCK
                                args("alamin", "flight", "READ", Decision.PERMIT, "support-exec can read flight"),
                                args("alamin", "pnl", "READ", Decision.PERMIT, "support-exec can read pnl (role)"),
                                args("alamin", "pnl", "BLOCK", Decision.PERMIT,
                                                "support-exec can block pnl (extra perm via ABAC)"),
                                args("alamin", "price", "BLOCK", Decision.DENY, "support-exec has no price:BLOCK"),
                                args("alamin", "pnr", "READ", Decision.DENY, "support-exec has no pnr access"),
                                args("alamin", "price", "READ", Decision.DENY, "support-exec has no price access"),

                                // ── support-executive: Hasbullah (flight:READ, pnl:READ) + extra: price:READ
                                args("hasbullah", "flight", "READ", Decision.PERMIT, "support-exec can read flight"),
                                args("hasbullah", "pnl", "READ", Decision.PERMIT, "support-exec can read pnl (role)"),
                                args("hasbullah", "price", "READ", Decision.PERMIT,
                                                "support-exec can read price (extra perm via ABAC)"),
                                args("hasbullah", "price", "BLOCK", Decision.DENY, "support-exec has no price:BLOCK"),
                                args("hasbullah", "pnl", "BLOCK", Decision.DENY, "support-exec has no pnl:BLOCK"),
                                args("hasbullah", "pnr", "READ", Decision.DENY, "support-exec has no pnr access"),

                                // ── booking-agent: Nafi (flight:READ, pnr CRUD, no extras) ───────────
                                args("nafi", "flight", "READ", Decision.PERMIT, "booking-agent can read flight"),
                                args("nafi", "pnr", "READ", Decision.PERMIT, "booking-agent can read pnr"),
                                args("nafi", "pnr", "CREATE", Decision.PERMIT, "booking-agent can create pnr"),
                                args("nafi", "pnr", "UPDATE", Decision.PERMIT, "booking-agent can update pnr"),
                                args("nafi", "pnr", "DELETE", Decision.PERMIT, "booking-agent can delete pnr"),
                                args("nafi", "pnl", "READ", Decision.DENY, "booking-agent has no pnl access"),
                                args("nafi", "price", "BLOCK", Decision.DENY, "booking-agent has no price:BLOCK"),
                                args("nafi", "price", "READ", Decision.DENY, "booking-agent has no price access"),

                                // ── sale-executive: Nahian (price+sales CRUD) + extra: pnr:READ ───────
                                args("nahian", "sales", "READ", Decision.PERMIT, "sale-exec can read sales"),
                                args("nahian", "sales", "CREATE", Decision.PERMIT, "sale-exec can create sales"),
                                args("nahian", "price", "READ", Decision.PERMIT, "sale-exec can read price"),
                                args("nahian", "pnr", "READ", Decision.PERMIT,
                                                "sale-exec can read pnr (extra perm via ABAC)"),
                                args("nahian", "pnr", "CREATE", Decision.DENY,
                                                "sale-exec has no pnr:CREATE (only READ via extra perm)"),
                                args("nahian", "pnl", "READ", Decision.DENY, "sale-exec has no pnl access"),
                                args("nahian", "price", "BLOCK", Decision.DENY, "sale-exec has no price:BLOCK"),

                                // ── sale-executive: Kiron (price+sales CRUD, no extras) ──────────────
                                args("kiron", "sales", "CREATE", Decision.PERMIT, "sale-exec can create sales"),
                                args("kiron", "price", "DELETE", Decision.PERMIT, "sale-exec can delete price"),
                                args("kiron", "pnr", "READ", Decision.DENY, "sale-exec has no pnr access"),
                                args("kiron", "pnl", "BLOCK", Decision.DENY, "sale-exec has no pnl:BLOCK"),
                                args("kiron", "flight", "READ", Decision.DENY, "sale-exec has no flight access"));
        }

        private static Arguments args(String user, String resource, String action,
                        Decision expected, String description) {
                return Arguments.of(user, resource, action, expected, description);
        }

        @ParameterizedTest(name = "[{index}] {0}:{1}:{2} → {3} ({4})")
        @MethodSource("authorizationScenarios")
        @DisplayName("Authorization scenarios from example-usecase.md")
        void verifyAuthorizationDecision(String externalSubjectId,
                        String resource,
                        String action,
                        Decision expectedDecision,
                        String description) {
                AuthorizationRequest request = AuthorizationRequest.builder()
                                .tenantId(TENANT)
                                .externalSubjectId(externalSubjectId)
                                .resource(resource)
                                .action(action)
                                .build();

                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                HttpEntity<AuthorizationRequest> entity = new HttpEntity<>(request, headers);

                AuthorizationResponse response = restTemplate.postForObject(
                                url(), entity, AuthorizationResponse.class);

                assertThat(response)
                                .as("Response must not be null for: %s", description)
                                .isNotNull();
                assertThat(response.decision())
                                .as("%s → %s:%s should be %s. Reason: %s",
                                                externalSubjectId, resource, action, expectedDecision,
                                                response != null ? response.reason() : "null response")
                                .isEqualTo(expectedDecision);
        }
}
