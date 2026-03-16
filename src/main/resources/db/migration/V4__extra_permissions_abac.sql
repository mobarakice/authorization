-- PSS Example Tenant: Option B implementation
-- Implements example-usecase.md scenario using HYBRID (OR) mode.
-- Extra per-user permissions are granted via ABAC policies that check
-- the subject's `extra_permissions` attribute loaded from subject_attributes.
--
-- Tenant: pss-example
-- Subjects: Mobarak, Mahtab, Shamim, Alamin, Hasbullah, Nafi, Nahian, Kiron

-- =====================================================
-- RESOURCES
-- =====================================================

INSERT INTO resources (id, tenant_id, name, type, description, active) VALUES
(78, 'pss-example', 'flight', 'PSS_MODULE', 'Airline operation on specific route', true),
(79, 'pss-example', 'pnr',    'PSS_MODULE', 'Passenger Name Record',               true),
(80, 'pss-example', 'pnl',    'PSS_MODULE', 'Passenger Name List',                 true),
(81, 'pss-example', 'price',  'PSS_MODULE', 'Ticket pricing',                      true),
(82, 'pss-example', 'sales',  'PSS_MODULE', 'Sales and marketing',                 true);

-- =====================================================
-- PERMISSIONS (bit_index scoped per tenant; starts at 0 for pss-example)
-- =====================================================

INSERT INTO permissions (id, tenant_id, name, action, resource_id, bit_index, description, active) VALUES
-- Flight (0-3)
(83, 'pss-example', 'flight:READ',   'READ',   78, 0,  'View flights',         true),
(84, 'pss-example', 'flight:CREATE', 'CREATE', 78, 1,  'Create flights',       true),
(85, 'pss-example', 'flight:UPDATE', 'UPDATE', 78, 2,  'Update flights',       true),
(86, 'pss-example', 'flight:DELETE', 'DELETE', 78, 3,  'Delete flights',       true),

-- PNR (10-13)
(87, 'pss-example', 'pnr:READ',   'READ',   79, 10, 'View PNR',             true),
(88, 'pss-example', 'pnr:CREATE', 'CREATE', 79, 11, 'Create PNR',           true),
(89, 'pss-example', 'pnr:UPDATE', 'UPDATE', 79, 12, 'Update PNR',           true),
(90, 'pss-example', 'pnr:DELETE', 'DELETE', 79, 13, 'Delete PNR',           true),

-- PNL (20-24, 24=BLOCK extra)
(91, 'pss-example', 'pnl:READ',   'READ',   80, 20, 'View PNL',             true),
(92, 'pss-example', 'pnl:CREATE', 'CREATE', 80, 21, 'Create PNL',           true),
(93, 'pss-example', 'pnl:UPDATE', 'UPDATE', 80, 22, 'Update PNL',           true),
(94, 'pss-example', 'pnl:DELETE', 'DELETE', 80, 23, 'Delete PNL',           true),
(95, 'pss-example', 'pnl:BLOCK',  'BLOCK',  80, 24, 'Block PNL record',     true),

-- Price (30-34, 34=BLOCK extra)
(96, 'pss-example', 'price:READ',   'READ',   81, 30, 'View price',           true),
(97, 'pss-example', 'price:CREATE', 'CREATE', 81, 31, 'Create price',         true),
(98, 'pss-example', 'price:UPDATE', 'UPDATE', 81, 32, 'Update price',         true),
(99, 'pss-example', 'price:DELETE', 'DELETE', 81, 33, 'Delete price',         true),
(100, 'pss-example', 'price:BLOCK',  'BLOCK',  81, 34, 'Block price record',   true),

-- Sales (40-43)
(101, 'pss-example', 'sales:READ',   'READ',   82, 40, 'View sales',           true),
(102, 'pss-example', 'sales:CREATE', 'CREATE', 82, 41, 'Create sales record',  true),
(103, 'pss-example', 'sales:UPDATE', 'UPDATE', 82, 42, 'Update sales record',  true),
(104, 'pss-example', 'sales:DELETE', 'DELETE', 82, 43, 'Delete sales record',  true);

-- =====================================================
-- ROLES
-- =====================================================

INSERT INTO roles (id, tenant_id, name, description, system_role, hierarchy_depth, active) VALUES
(105, 'pss-example', 'super-admin',        'System administrator',         true,  2, true),
(106, 'pss-example', 'admin',              'Executive administrator',      false, 1, true),
(107, 'pss-example', 'support-executive',  'Support staff',                false, 0, true),
(108, 'pss-example', 'booking-agent',      'Reservation agent',            false, 0, true),
(109, 'pss-example', 'sale-executive',     'Sales and marketing officer',  false, 0, true);

-- =====================================================
-- ROLE-PERMISSION ASSIGNMENTS
-- =====================================================

-- Super Admin: ALL CRUD on ALL resources (BLOCK not granted via role — extra permission only)
INSERT INTO role_permissions (role_id, permission_id) VALUES
(105, 83), -- flight:READ
(105, 84), -- flight:CREATE
(105, 85), -- flight:UPDATE
(105, 86), -- flight:DELETE
(105, 87), -- pnr:READ
(105, 88), -- pnr:CREATE
(105, 89), -- pnr:UPDATE
(105, 90), -- pnr:DELETE
(105, 91), -- pnl:READ
(105, 92), -- pnl:CREATE
(105, 93), -- pnl:UPDATE
(105, 94), -- pnl:DELETE
(105, 96), -- price:READ
(105, 97), -- price:CREATE
(105, 98), -- price:UPDATE
(105, 99), -- price:DELETE
(105, 101), -- sales:READ
(105, 102), -- sales:CREATE
(105, 103), -- sales:UPDATE
(105, 104); -- sales:DELETE

-- Admin: Flight, Price, Sales (all CRUD)
INSERT INTO role_permissions (role_id, permission_id) VALUES
(106, 83), -- flight:READ
(106, 84), -- flight:CREATE
(106, 85), -- flight:UPDATE
(106, 86), -- flight:DELETE
(106, 96), -- price:READ
(106, 97), -- price:CREATE
(106, 98), -- price:UPDATE
(106, 99), -- price:DELETE
(106, 101), -- sales:READ
(106, 102), -- sales:CREATE
(106, 103), -- sales:UPDATE
(106, 104); -- sales:DELETE

-- Support Executive: Flight(READ), PNL(READ)
INSERT INTO role_permissions (role_id, permission_id) VALUES
(107, 83), -- flight:READ
(107, 91); -- pnl:READ

-- Booking Agent: Flight(READ), PNR (all CRUD)
INSERT INTO role_permissions (role_id, permission_id) VALUES
(108, 83), -- flight:READ
(108, 87), -- pnr:READ
(108, 88), -- pnr:CREATE
(108, 89), -- pnr:UPDATE
(108, 90); -- pnr:DELETE

-- Sale Executive: Price, Sales (all CRUD)
INSERT INTO role_permissions (role_id, permission_id) VALUES
(109, 96), -- price:READ
(109, 97), -- price:CREATE
(109, 98), -- price:UPDATE
(109, 99), -- price:DELETE
(109, 101), -- sales:READ
(109, 102), -- sales:CREATE
(109, 103), -- sales:UPDATE
(109, 104); -- sales:DELETE

-- =====================================================
-- SUBJECTS
-- =====================================================

INSERT INTO subjects (id, tenant_id, external_id, subject_type, display_name, active) VALUES
(110, 'pss-example', 'mobarak',   'USER', 'Mobarak',   true),
(111, 'pss-example', 'mahtab',    'USER', 'Mahtab',    true),
(112, 'pss-example', 'shamim',    'USER', 'Shamim',    true),
(113, 'pss-example', 'alamin',    'USER', 'Alamin',    true),
(114, 'pss-example', 'hasbullah', 'USER', 'Hasbullah', true),
(115, 'pss-example', 'nafi',      'USER', 'Nafi',      true),
(116, 'pss-example', 'nahian',    'USER', 'Nahian',    true),
(117, 'pss-example', 'kiron',     'USER', 'Kiron',     true);

-- =====================================================
-- SUBJECT-ROLE ASSIGNMENTS
-- =====================================================

INSERT INTO subject_roles (subject_id, role_id) VALUES
(110, 105), -- Mobarak  -> super-admin
(111, 106), -- Mahtab   -> admin
(112, 106), -- Shamim   -> admin
(113, 107), -- Alamin   -> support-executive
(114, 107), -- Hasbullah -> support-executive
(115, 108), -- Nafi     -> booking-agent
(116, 109), -- Nahian   -> sale-executive
(117, 109); -- Kiron    -> sale-executive

-- =====================================================
-- ATTRIBUTE DEFINITION: extra_permissions
-- Stores comma-separated resource:ACTION grants beyond the subject's role.
-- Loaded by AuthorizationService.enrichSubjectAttributes() and evaluated
-- by ABAC policies using the CONTAINS operator.
-- =====================================================

INSERT INTO attribute_definitions (id, tenant_id, name, display_name, category, data_type, source, description, required, active) VALUES
(118, 'pss-example', 'extra_permissions',
 'Extra Permissions', 'SUBJECT', 'STRING', 'USER_PROFILE',
 'Comma-separated list of resource:ACTION grants beyond the role (e.g. price:BLOCK)', false, true);

-- =====================================================
-- SUBJECT ATTRIBUTES: extra permissions per user
-- Only users with grants beyond their role have this attribute.
-- AuthorizationService loads these and injects them into the request
-- before ABAC evaluation.
-- =====================================================

INSERT INTO subject_attributes (id, subject_id, attribute_name, attribute_value, value_type) VALUES
-- Shamim (admin) + Price->Block
(119, 112, 'extra_permissions', 'price:BLOCK',  'STRING'),
-- Alamin (support-executive) + PNL->Block
(120, 113, 'extra_permissions', 'pnl:BLOCK',    'STRING'),
-- Hasbullah (support-executive) + Price->Read (additive: role has no price permissions) + PNR->Read
(121, 114, 'extra_permissions', 'price:READ,pnr:READ', 'STRING'),
-- Nahian (sale-executive) + PNR->Read (additive: role has no pnr permissions)
(122, 116, 'extra_permissions', 'pnr:READ',     'STRING');

-- =====================================================
-- ABAC POLICIES: extra permission grants
-- One policy per extra-permission type (resource+action).
-- Effect=PERMIT, evaluated when AuthorizationService has enriched
-- the request with the subject's extra_permissions attribute.
-- Uses DENY_OVERRIDES combining; these are pure PERMIT policies with
-- no DENY rules, so they either PERMIT (attribute matches) or return
-- NOT_APPLICABLE (attribute absent or no match), never DENY.
-- =====================================================

INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, combining_algorithm, version, active) VALUES
(123, 'pss-example',
 'extra-perm-price-block',
 'Grant price:BLOCK to subjects whose extra_permissions attribute contains price:BLOCK',
 'price', 'BLOCK', 'PERMIT', 50, 'DENY_OVERRIDES', 0, true),

(124, 'pss-example',
 'extra-perm-pnl-block',
 'Grant pnl:BLOCK to subjects whose extra_permissions attribute contains pnl:BLOCK',
 'pnl', 'BLOCK', 'PERMIT', 50, 'DENY_OVERRIDES', 0, true),

(125, 'pss-example',
 'extra-perm-price-read',
 'Grant price:READ to subjects whose extra_permissions attribute contains price:READ',
 'price', 'READ', 'PERMIT', 50, 'DENY_OVERRIDES', 0, true),

(126, 'pss-example',
 'extra-perm-pnr-read',
 'Grant pnr:READ to subjects whose extra_permissions attribute contains pnr:READ',
 'pnr', 'READ', 'PERMIT', 50, 'DENY_OVERRIDES', 0, true);


-- Policy rules (one rule per policy, AND logic)

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
(127, 123, 'has-price-block-grant', 'AND', 0, true),
(128, 124, 'has-pnl-block-grant',   'AND', 0, true),
(129, 125, 'has-price-read-grant',  'AND', 0, true),
(130, 126, 'has-pnr-read-grant',    'AND', 0, true);

-- Rule conditions:
-- attribute = extra_permissions (SUBJECT category)
-- operator  = CONTAINS (substring match; safe because permission strings are distinct)
-- expected_value = the specific "resource:ACTION" string required

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate, order_index) VALUES
(127, 118, 'CONTAINS', 'price:BLOCK', false, 0),
(128, 118, 'CONTAINS', 'pnl:BLOCK',   false, 0),
(129, 118, 'CONTAINS', 'price:READ',  false, 0),
(130, 118, 'CONTAINS', 'pnr:READ',    false, 0);

-- =====================================================
-- AUTHORIZATION CONTEXTS
--
-- Resources with extra-permission ABAC policies → HYBRID / OR strategy:
--   OR means RBAC or ABAC can independently grant access.
--   - Normal subjects: RBAC grants via role → PERMIT (ABAC never runs).
--   - Extra-perm subjects: RBAC may deny → ABAC grants via policy → PERMIT.
--
-- Resources without extra permissions → pure RBAC (fastest path).
-- =====================================================

INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
(131, 'pss-example',
 'price-hybrid-context',
 'price: OR strategy — role-based access OR extra_permissions ABAC grant',
 'price', 'HYBRID', 'OR', 100, true),

(132, 'pss-example',
 'pnl-hybrid-context',
 'pnl: OR strategy — role-based access OR extra_permissions ABAC grant',
 'pnl', 'HYBRID', 'OR', 100, true),

(133, 'pss-example',
 'pnr-hybrid-context',
 'pnr: OR strategy — role-based access OR extra_permissions ABAC grant',
 'pnr', 'HYBRID', 'OR', 100, true),

(134, 'pss-example',
 'flight-rbac-context',
 'flight: pure RBAC — no extra permission grants defined',
 'flight', 'RBAC', NULL, 100, true),

(135, 'pss-example',
 'sales-rbac-context',
 'sales: pure RBAC — no extra permission grants defined',
 'sales', 'RBAC', NULL, 100, true);
