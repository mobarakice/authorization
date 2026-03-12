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
('a1111111-1111-1111-1111-111111110001', 'pss-example', 'flight', 'PSS_MODULE', 'Airline operation on specific route', true),
('a1111111-1111-1111-1111-111111110002', 'pss-example', 'pnr',    'PSS_MODULE', 'Passenger Name Record',               true),
('a1111111-1111-1111-1111-111111110003', 'pss-example', 'pnl',    'PSS_MODULE', 'Passenger Name List',                 true),
('a1111111-1111-1111-1111-111111110004', 'pss-example', 'price',  'PSS_MODULE', 'Ticket pricing',                      true),
('a1111111-1111-1111-1111-111111110005', 'pss-example', 'sales',  'PSS_MODULE', 'Sales and marketing',                 true);

-- =====================================================
-- PERMISSIONS (bit_index scoped per tenant; starts at 0 for pss-example)
-- =====================================================

INSERT INTO permissions (id, tenant_id, name, action, resource_id, bit_index, description, active) VALUES
-- Flight (0-3)
('a2222222-2222-2222-2222-222222220001', 'pss-example', 'flight:READ',   'READ',   'a1111111-1111-1111-1111-111111110001', 0,  'View flights',         true),
('a2222222-2222-2222-2222-222222220002', 'pss-example', 'flight:CREATE', 'CREATE', 'a1111111-1111-1111-1111-111111110001', 1,  'Create flights',       true),
('a2222222-2222-2222-2222-222222220003', 'pss-example', 'flight:UPDATE', 'UPDATE', 'a1111111-1111-1111-1111-111111110001', 2,  'Update flights',       true),
('a2222222-2222-2222-2222-222222220004', 'pss-example', 'flight:DELETE', 'DELETE', 'a1111111-1111-1111-1111-111111110001', 3,  'Delete flights',       true),

-- PNR (10-13)
('a2222222-2222-2222-2222-222222220010', 'pss-example', 'pnr:READ',   'READ',   'a1111111-1111-1111-1111-111111110002', 10, 'View PNR',             true),
('a2222222-2222-2222-2222-222222220011', 'pss-example', 'pnr:CREATE', 'CREATE', 'a1111111-1111-1111-1111-111111110002', 11, 'Create PNR',           true),
('a2222222-2222-2222-2222-222222220012', 'pss-example', 'pnr:UPDATE', 'UPDATE', 'a1111111-1111-1111-1111-111111110002', 12, 'Update PNR',           true),
('a2222222-2222-2222-2222-222222220013', 'pss-example', 'pnr:DELETE', 'DELETE', 'a1111111-1111-1111-1111-111111110002', 13, 'Delete PNR',           true),

-- PNL (20-24, 24=BLOCK extra)
('a2222222-2222-2222-2222-222222220020', 'pss-example', 'pnl:READ',   'READ',   'a1111111-1111-1111-1111-111111110003', 20, 'View PNL',             true),
('a2222222-2222-2222-2222-222222220021', 'pss-example', 'pnl:CREATE', 'CREATE', 'a1111111-1111-1111-1111-111111110003', 21, 'Create PNL',           true),
('a2222222-2222-2222-2222-222222220022', 'pss-example', 'pnl:UPDATE', 'UPDATE', 'a1111111-1111-1111-1111-111111110003', 22, 'Update PNL',           true),
('a2222222-2222-2222-2222-222222220023', 'pss-example', 'pnl:DELETE', 'DELETE', 'a1111111-1111-1111-1111-111111110003', 23, 'Delete PNL',           true),
('a2222222-2222-2222-2222-222222220024', 'pss-example', 'pnl:BLOCK',  'BLOCK',  'a1111111-1111-1111-1111-111111110003', 24, 'Block PNL record',     true),

-- Price (30-34, 34=BLOCK extra)
('a2222222-2222-2222-2222-222222220030', 'pss-example', 'price:READ',   'READ',   'a1111111-1111-1111-1111-111111110004', 30, 'View price',           true),
('a2222222-2222-2222-2222-222222220031', 'pss-example', 'price:CREATE', 'CREATE', 'a1111111-1111-1111-1111-111111110004', 31, 'Create price',         true),
('a2222222-2222-2222-2222-222222220032', 'pss-example', 'price:UPDATE', 'UPDATE', 'a1111111-1111-1111-1111-111111110004', 32, 'Update price',         true),
('a2222222-2222-2222-2222-222222220033', 'pss-example', 'price:DELETE', 'DELETE', 'a1111111-1111-1111-1111-111111110004', 33, 'Delete price',         true),
('a2222222-2222-2222-2222-222222220034', 'pss-example', 'price:BLOCK',  'BLOCK',  'a1111111-1111-1111-1111-111111110004', 34, 'Block price record',   true),

-- Sales (40-43)
('a2222222-2222-2222-2222-222222220040', 'pss-example', 'sales:READ',   'READ',   'a1111111-1111-1111-1111-111111110005', 40, 'View sales',           true),
('a2222222-2222-2222-2222-222222220041', 'pss-example', 'sales:CREATE', 'CREATE', 'a1111111-1111-1111-1111-111111110005', 41, 'Create sales record',  true),
('a2222222-2222-2222-2222-222222220042', 'pss-example', 'sales:UPDATE', 'UPDATE', 'a1111111-1111-1111-1111-111111110005', 42, 'Update sales record',  true),
('a2222222-2222-2222-2222-222222220043', 'pss-example', 'sales:DELETE', 'DELETE', 'a1111111-1111-1111-1111-111111110005', 43, 'Delete sales record',  true);

-- =====================================================
-- ROLES
-- =====================================================

INSERT INTO roles (id, tenant_id, name, description, system_role, hierarchy_depth, active) VALUES
('a3333333-3333-3333-3333-333333330001', 'pss-example', 'super-admin',        'System administrator',         true,  2, true),
('a3333333-3333-3333-3333-333333330002', 'pss-example', 'admin',              'Executive administrator',      false, 1, true),
('a3333333-3333-3333-3333-333333330003', 'pss-example', 'support-executive',  'Support staff',                false, 0, true),
('a3333333-3333-3333-3333-333333330004', 'pss-example', 'booking-agent',      'Reservation agent',            false, 0, true),
('a3333333-3333-3333-3333-333333330005', 'pss-example', 'sale-executive',     'Sales and marketing officer',  false, 0, true);

-- =====================================================
-- ROLE-PERMISSION ASSIGNMENTS
-- =====================================================

-- Super Admin: ALL CRUD on ALL resources (BLOCK not granted via role — extra permission only)
INSERT INTO role_permissions (role_id, permission_id) VALUES
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220001'), -- flight:READ
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220002'), -- flight:CREATE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220003'), -- flight:UPDATE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220004'), -- flight:DELETE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220010'), -- pnr:READ
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220011'), -- pnr:CREATE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220012'), -- pnr:UPDATE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220013'), -- pnr:DELETE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220020'), -- pnl:READ
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220021'), -- pnl:CREATE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220022'), -- pnl:UPDATE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220023'), -- pnl:DELETE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220030'), -- price:READ
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220031'), -- price:CREATE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220032'), -- price:UPDATE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220033'), -- price:DELETE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220040'), -- sales:READ
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220041'), -- sales:CREATE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220042'), -- sales:UPDATE
('a3333333-3333-3333-3333-333333330001', 'a2222222-2222-2222-2222-222222220043'); -- sales:DELETE

-- Admin: Flight, Price, Sales (all CRUD)
INSERT INTO role_permissions (role_id, permission_id) VALUES
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220001'), -- flight:READ
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220002'), -- flight:CREATE
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220003'), -- flight:UPDATE
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220004'), -- flight:DELETE
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220030'), -- price:READ
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220031'), -- price:CREATE
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220032'), -- price:UPDATE
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220033'), -- price:DELETE
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220040'), -- sales:READ
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220041'), -- sales:CREATE
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220042'), -- sales:UPDATE
('a3333333-3333-3333-3333-333333330002', 'a2222222-2222-2222-2222-222222220043'); -- sales:DELETE

-- Support Executive: Flight(READ), PNL(READ)
INSERT INTO role_permissions (role_id, permission_id) VALUES
('a3333333-3333-3333-3333-333333330003', 'a2222222-2222-2222-2222-222222220001'), -- flight:READ
('a3333333-3333-3333-3333-333333330003', 'a2222222-2222-2222-2222-222222220020'); -- pnl:READ

-- Booking Agent: Flight(READ), PNR (all CRUD)
INSERT INTO role_permissions (role_id, permission_id) VALUES
('a3333333-3333-3333-3333-333333330004', 'a2222222-2222-2222-2222-222222220001'), -- flight:READ
('a3333333-3333-3333-3333-333333330004', 'a2222222-2222-2222-2222-222222220010'), -- pnr:READ
('a3333333-3333-3333-3333-333333330004', 'a2222222-2222-2222-2222-222222220011'), -- pnr:CREATE
('a3333333-3333-3333-3333-333333330004', 'a2222222-2222-2222-2222-222222220012'), -- pnr:UPDATE
('a3333333-3333-3333-3333-333333330004', 'a2222222-2222-2222-2222-222222220013'); -- pnr:DELETE

-- Sale Executive: Price, Sales (all CRUD)
INSERT INTO role_permissions (role_id, permission_id) VALUES
('a3333333-3333-3333-3333-333333330005', 'a2222222-2222-2222-2222-222222220030'), -- price:READ
('a3333333-3333-3333-3333-333333330005', 'a2222222-2222-2222-2222-222222220031'), -- price:CREATE
('a3333333-3333-3333-3333-333333330005', 'a2222222-2222-2222-2222-222222220032'), -- price:UPDATE
('a3333333-3333-3333-3333-333333330005', 'a2222222-2222-2222-2222-222222220033'), -- price:DELETE
('a3333333-3333-3333-3333-333333330005', 'a2222222-2222-2222-2222-222222220040'), -- sales:READ
('a3333333-3333-3333-3333-333333330005', 'a2222222-2222-2222-2222-222222220041'), -- sales:CREATE
('a3333333-3333-3333-3333-333333330005', 'a2222222-2222-2222-2222-222222220042'), -- sales:UPDATE
('a3333333-3333-3333-3333-333333330005', 'a2222222-2222-2222-2222-222222220043'); -- sales:DELETE

-- =====================================================
-- SUBJECTS
-- =====================================================

INSERT INTO subjects (id, tenant_id, external_id, subject_type, display_name, active) VALUES
('a4444444-4444-4444-4444-444444440001', 'pss-example', 'mobarak',   'USER', 'Mobarak',   true),
('a4444444-4444-4444-4444-444444440002', 'pss-example', 'mahtab',    'USER', 'Mahtab',    true),
('a4444444-4444-4444-4444-444444440003', 'pss-example', 'shamim',    'USER', 'Shamim',    true),
('a4444444-4444-4444-4444-444444440004', 'pss-example', 'alamin',    'USER', 'Alamin',    true),
('a4444444-4444-4444-4444-444444440005', 'pss-example', 'hasbullah', 'USER', 'Hasbullah', true),
('a4444444-4444-4444-4444-444444440006', 'pss-example', 'nafi',      'USER', 'Nafi',      true),
('a4444444-4444-4444-4444-444444440007', 'pss-example', 'nahian',    'USER', 'Nahian',    true),
('a4444444-4444-4444-4444-444444440008', 'pss-example', 'kiron',     'USER', 'Kiron',     true);

-- =====================================================
-- SUBJECT-ROLE ASSIGNMENTS
-- =====================================================

INSERT INTO subject_roles (subject_id, role_id) VALUES
('a4444444-4444-4444-4444-444444440001', 'a3333333-3333-3333-3333-333333330001'), -- Mobarak  -> super-admin
('a4444444-4444-4444-4444-444444440002', 'a3333333-3333-3333-3333-333333330002'), -- Mahtab   -> admin
('a4444444-4444-4444-4444-444444440003', 'a3333333-3333-3333-3333-333333330002'), -- Shamim   -> admin
('a4444444-4444-4444-4444-444444440004', 'a3333333-3333-3333-3333-333333330003'), -- Alamin   -> support-executive
('a4444444-4444-4444-4444-444444440005', 'a3333333-3333-3333-3333-333333330003'), -- Hasbullah -> support-executive
('a4444444-4444-4444-4444-444444440006', 'a3333333-3333-3333-3333-333333330004'), -- Nafi     -> booking-agent
('a4444444-4444-4444-4444-444444440007', 'a3333333-3333-3333-3333-333333330005'), -- Nahian   -> sale-executive
('a4444444-4444-4444-4444-444444440008', 'a3333333-3333-3333-3333-333333330005'); -- Kiron    -> sale-executive

-- =====================================================
-- ATTRIBUTE DEFINITION: extra_permissions
-- Stores comma-separated resource:ACTION grants beyond the subject's role.
-- Loaded by AuthorizationService.enrichSubjectAttributes() and evaluated
-- by ABAC policies using the CONTAINS operator.
-- =====================================================

INSERT INTO attribute_definitions (id, tenant_id, name, display_name, category, data_type, source, description, active) VALUES
('a5555555-5555-5555-5555-555555550001', 'pss-example', 'extra_permissions',
 'Extra Permissions', 'SUBJECT', 'STRING', 'USER_PROFILE',
 'Comma-separated list of resource:ACTION grants beyond the role (e.g. price:BLOCK)', true);

-- =====================================================
-- SUBJECT ATTRIBUTES: extra permissions per user
-- Only users with grants beyond their role have this attribute.
-- AuthorizationService loads these and injects them into the request
-- before ABAC evaluation.
-- =====================================================

INSERT INTO subject_attributes (id, subject_id, attribute_name, attribute_value, value_type) VALUES
-- Shamim (admin) + Price->Block
('a6666666-6666-6666-6666-666666660001', 'a4444444-4444-4444-4444-444444440003', 'extra_permissions', 'price:BLOCK',  'STRING'),
-- Alamin (support-executive) + PNL->Block
('a6666666-6666-6666-6666-666666660002', 'a4444444-4444-4444-4444-444444440004', 'extra_permissions', 'pnl:BLOCK',    'STRING'),
-- Hasbullah (support-executive) + Price->Read (additive: role has no price permissions)
('a6666666-6666-6666-6666-666666660003', 'a4444444-4444-4444-4444-444444440005', 'extra_permissions', 'price:READ',   'STRING'),
-- Nahian (sale-executive) + PNR->Read (additive: role has no pnr permissions)
('a6666666-6666-6666-6666-666666660004', 'a4444444-4444-4444-4444-444444440007', 'extra_permissions', 'pnr:READ',     'STRING');

-- =====================================================
-- ABAC POLICIES: extra permission grants
-- One policy per extra-permission type (resource+action).
-- Effect=PERMIT, evaluated when AuthorizationService has enriched
-- the request with the subject's extra_permissions attribute.
-- Uses DENY_OVERRIDES combining; these are pure PERMIT policies with
-- no DENY rules, so they either PERMIT (attribute matches) or return
-- NOT_APPLICABLE (attribute absent or no match), never DENY.
-- =====================================================

INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, combining_algorithm, active) VALUES
('a7777777-7777-7777-7777-777777770001', 'pss-example',
 'extra-perm-price-block',
 'Grant price:BLOCK to subjects whose extra_permissions attribute contains price:BLOCK',
 'price', 'BLOCK', 'PERMIT', 50, 'DENY_OVERRIDES', true),

('a7777777-7777-7777-7777-777777770002', 'pss-example',
 'extra-perm-pnl-block',
 'Grant pnl:BLOCK to subjects whose extra_permissions attribute contains pnl:BLOCK',
 'pnl', 'BLOCK', 'PERMIT', 50, 'DENY_OVERRIDES', true),

('a7777777-7777-7777-7777-777777770003', 'pss-example',
 'extra-perm-price-read',
 'Grant price:READ to subjects whose extra_permissions attribute contains price:READ',
 'price', 'READ', 'PERMIT', 50, 'DENY_OVERRIDES', true),

('a7777777-7777-7777-7777-777777770004', 'pss-example',
 'extra-perm-pnr-read',
 'Grant pnr:READ to subjects whose extra_permissions attribute contains pnr:READ',
 'pnr', 'READ', 'PERMIT', 50, 'DENY_OVERRIDES', true);

-- Policy rules (one rule per policy, AND logic)

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
('a8888888-8888-8888-8888-888888880001', 'a7777777-7777-7777-7777-777777770001', 'has-price-block-grant', 'AND', 0, true),
('a8888888-8888-8888-8888-888888880002', 'a7777777-7777-7777-7777-777777770002', 'has-pnl-block-grant',   'AND', 0, true),
('a8888888-8888-8888-8888-888888880003', 'a7777777-7777-7777-7777-777777770003', 'has-price-read-grant',  'AND', 0, true),
('a8888888-8888-8888-8888-888888880004', 'a7777777-7777-7777-7777-777777770004', 'has-pnr-read-grant',    'AND', 0, true);

-- Rule conditions:
-- attribute = extra_permissions (SUBJECT category)
-- operator  = CONTAINS (substring match; safe because permission strings are distinct)
-- expected_value = the specific "resource:ACTION" string required

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate, order_index) VALUES
('a8888888-8888-8888-8888-888888880001', 'a5555555-5555-5555-5555-555555550001', 'CONTAINS', 'price:BLOCK', false, 0),
('a8888888-8888-8888-8888-888888880002', 'a5555555-5555-5555-5555-555555550001', 'CONTAINS', 'pnl:BLOCK',   false, 0),
('a8888888-8888-8888-8888-888888880003', 'a5555555-5555-5555-5555-555555550001', 'CONTAINS', 'price:READ',  false, 0),
('a8888888-8888-8888-8888-888888880004', 'a5555555-5555-5555-5555-555555550001', 'CONTAINS', 'pnr:READ',    false, 0);

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
('a9999999-9999-9999-9999-999999990001', 'pss-example',
 'price-hybrid-context',
 'price: OR strategy — role-based access OR extra_permissions ABAC grant',
 'price', 'HYBRID', 'OR', 100, true),

('a9999999-9999-9999-9999-999999990002', 'pss-example',
 'pnl-hybrid-context',
 'pnl: OR strategy — role-based access OR extra_permissions ABAC grant',
 'pnl', 'HYBRID', 'OR', 100, true),

('a9999999-9999-9999-9999-999999990003', 'pss-example',
 'pnr-hybrid-context',
 'pnr: OR strategy — role-based access OR extra_permissions ABAC grant',
 'pnr', 'HYBRID', 'OR', 100, true),

('a9999999-9999-9999-9999-999999990004', 'pss-example',
 'flight-rbac-context',
 'flight: pure RBAC — no extra permission grants defined',
 'flight', 'RBAC', NULL, 100, true),

('a9999999-9999-9999-9999-999999990005', 'pss-example',
 'sales-rbac-context',
 'sales: pure RBAC — no extra permission grants defined',
 'sales', 'RBAC', NULL, 100, true);
