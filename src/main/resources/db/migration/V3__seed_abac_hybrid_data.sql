-- ABAC Policies and Hybrid Authorization for Airline PSS/DCS
-- Tenant: airline-pss

-- =====================================================
-- ATTRIBUTE DEFINITIONS
-- =====================================================

INSERT INTO attribute_definitions (id, tenant_id, name, display_name, category, data_type, source, description, active) VALUES
-- Subject Attributes
('55555555-5555-5555-5555-555555555101', 'airline-pss', 'department', 'Department', 'SUBJECT', 'STRING', 'USER_PROFILE', 'User department', true),
('55555555-5555-5555-5555-555555555102', 'airline-pss', 'location', 'Airport Location', 'SUBJECT', 'STRING', 'USER_PROFILE', 'User airport location', true),
('55555555-5555-5555-5555-555555555103', 'airline-pss', 'clearance_level', 'Security Clearance', 'SUBJECT', 'INTEGER', 'USER_PROFILE', 'Security clearance level', true),
('55555555-5555-5555-5555-555555555104', 'airline-pss', 'shift', 'Work Shift', 'SUBJECT', 'STRING', 'USER_PROFILE', 'Current work shift', true),

-- Resource Attributes
('55555555-5555-5555-5555-555555555201', 'airline-pss', 'flight_status', 'Flight Status', 'RESOURCE', 'STRING', 'RESOURCE_METADATA', 'Current flight status', true),
('55555555-5555-5555-5555-555555555202', 'airline-pss', 'departure_airport', 'Departure Airport', 'RESOURCE', 'STRING', 'RESOURCE_METADATA', 'Flight departure airport', true),
('55555555-5555-5555-5555-555555555203', 'airline-pss', 'data_classification', 'Data Classification', 'RESOURCE', 'STRING', 'RESOURCE_METADATA', 'Data sensitivity level', true),
('55555555-5555-5555-5555-555555555204', 'airline-pss', 'booking_class', 'Booking Class', 'RESOURCE', 'STRING', 'RESOURCE_METADATA', 'Fare booking class', true),

-- Environment Attributes
('55555555-5555-5555-5555-555555555301', 'airline-pss', 'time_of_day', 'Time of Day', 'ENVIRONMENT', 'TIME', 'SYSTEM', 'Current time', true),
('55555555-5555-5555-5555-555555555302', 'airline-pss', 'ip_address', 'IP Address', 'ENVIRONMENT', 'STRING', 'SYSTEM', 'Request IP address', true),
('55555555-5555-5555-5555-555555555303', 'airline-pss', 'device_type', 'Device Type', 'ENVIRONMENT', 'STRING', 'SYSTEM', 'Device type (kiosk, mobile, desktop)', true);

-- =====================================================
-- ABAC POLICIES
-- =====================================================

-- Policy 1: PII Access - Only during business hours and high clearance
INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, active) VALUES
('66666666-6666-6666-6666-666666666101', 'airline-pss', 'pii-access-policy', 
 'Restrict PII access to business hours and authorized personnel', 
 'passengers', 'PII_ACCESS', 'PERMIT', 100, true);

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
('77777777-7777-7777-7777-777777777101', '66666666-6666-6666-6666-666666666101', 'business-hours-and-clearance', 'AND', 0, true);

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate) VALUES
('77777777-7777-7777-7777-777777777101', '55555555-5555-5555-5555-555555555103', 'GREATER_THAN_OR_EQUAL', '3', false),
('77777777-7777-7777-7777-777777777101', '55555555-5555-5555-5555-555555555301', 'BETWEEN', '08:00', false);

-- Policy 2: Location-based Check-in
INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, active) VALUES
('66666666-6666-6666-6666-666666666102', 'airline-pss', 'location-based-checkin', 
 'Check-in agents can only process flights from their location', 
 'check-in', 'PERFORM', 'PERMIT', 90, true);

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
('77777777-7777-7777-7777-777777777102', '66666666-6666-6666-6666-666666666102', 'same-location-rule', 'AND', 0, true);

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate) VALUES
('77777777-7777-7777-7777-777777777102', '55555555-5555-5555-5555-555555555102', 'EQUALS', '${resource.departure_airport}', false);

-- Policy 3: Boarding Close - Only gate agents at departure location
INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, active) VALUES
('66666666-6666-6666-6666-666666666103', 'airline-pss', 'boarding-close-policy', 
 'Only gate agents at departure airport can close boarding', 
 'boarding', 'CLOSE', 'PERMIT', 95, true);

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
('77777777-7777-7777-7777-777777777103', '66666666-6666-6666-6666-666666666103', 'gate-agent-location', 'AND', 0, true);

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate) VALUES
('77777777-7777-7777-7777-777777777103', '55555555-5555-5555-5555-555555555101', 'EQUALS', 'gate-operations', false),
('77777777-7777-7777-7777-777777777103', '55555555-5555-5555-5555-555555555102', 'EQUALS', '${resource.departure_airport}', false);

-- Policy 4: Inventory Override - High clearance only
INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, active) VALUES
('66666666-6666-6666-6666-666666666104', 'airline-pss', 'inventory-override-policy', 
 'Inventory overrides require clearance level 4+', 
 'inventory', 'OVERRIDE', 'PERMIT', 100, true);

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
('77777777-7777-7777-7777-777777777104', '66666666-6666-6666-6666-666666666104', 'high-clearance', 'AND', 0, true);

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate) VALUES
('77777777-7777-7777-7777-777777777104', '55555555-5555-5555-5555-555555555103', 'GREATER_THAN_OR_EQUAL', '4', false);

-- Policy 5: Kiosk Restrictions
INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, active) VALUES
('66666666-6666-6666-6666-666666666105', 'airline-pss', 'kiosk-restriction-policy', 
 'Kiosks have limited access to sensitive operations', 
 'passengers', 'UPDATE', 'DENY', 80, true);

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
('77777777-7777-7777-7777-777777777105', '66666666-6666-6666-6666-666666666105', 'kiosk-device', 'AND', 0, true);

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate) VALUES
('77777777-7777-7777-7777-777777777105', '55555555-5555-5555-5555-555555555303', 'EQUALS', 'kiosk', false),
('77777777-7777-7777-7777-777777777105', '55555555-5555-5555-5555-555555555203', 'EQUALS', 'sensitive', false);

-- =====================================================
-- HYBRID AUTHORIZATION CONTEXTS
-- =====================================================

-- Context 1: Check-in Operations (Hybrid: RBAC + Location ABAC)
INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
('88888888-8888-8888-8888-888888888101', 'airline-pss', 'check-in-context', 
 'Check-in requires role AND location match', 
 'check-in', 'HYBRID', 'AND', 100, true);

INSERT INTO context_rules (context_id, rule_type, role_id, policy_id, required, priority, active) VALUES
('88888888-8888-8888-8888-888888888101', 'RBAC', '33333333-3333-3333-3333-333333333201', NULL, true, 100, true),
('88888888-8888-8888-8888-888888888101', 'ABAC', NULL, '66666666-6666-6666-6666-666666666102', true, 90, true);

-- Context 2: Boarding Operations (Hybrid: RBAC + ABAC)
INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
('88888888-8888-8888-8888-888888888102', 'airline-pss', 'boarding-context', 
 'Boarding requires gate agent role AND location', 
 'boarding', 'HYBRID', 'AND', 100, true);

INSERT INTO context_rules (context_id, rule_type, role_id, policy_id, required, priority, active) VALUES
('88888888-8888-8888-8888-888888888102', 'RBAC', '33333333-3333-3333-3333-333333333202', NULL, true, 100, true),
('88888888-8888-8888-8888-888888888102', 'ABAC', NULL, '66666666-6666-6666-6666-666666666103', true, 95, true);

-- Context 3: PII Access (Hybrid: RBAC OR ABAC with constraints)
INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
('88888888-8888-8888-8888-888888888103', 'airline-pss', 'pii-access-context', 
 'PII access requires role with time/clearance constraints', 
 'passengers', 'HYBRID', 'RBAC_REQUIRED_ABAC_CONSTRAINS', 100, true);

INSERT INTO context_rules (context_id, rule_type, role_id, policy_id, required, priority, active) VALUES
('88888888-8888-8888-8888-888888888103', 'RBAC', '33333333-3333-3333-3333-333333333302', NULL, true, 100, true),
('88888888-8888-8888-8888-888888888103', 'ABAC', NULL, '66666666-6666-6666-6666-666666666101', true, 100, true);

-- Context 4: Inventory Override (Pure ABAC)
INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
('88888888-8888-8888-8888-888888888104', 'airline-pss', 'inventory-override-context', 
 'Inventory overrides use clearance-based ABAC', 
 'inventory', 'ABAC', NULL, 90, true);

INSERT INTO context_rules (context_id, rule_type, role_id, policy_id, required, priority, active) VALUES
('88888888-8888-8888-8888-888888888104', 'ABAC', NULL, '66666666-6666-6666-6666-666666666104', true, 100, true);

-- Context 5: Reservations (Pure RBAC - simple and fast)
INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
('88888888-8888-8888-8888-888888888105', 'airline-pss', 'reservations-context', 
 'Reservations use simple RBAC for speed', 
 'reservations', 'RBAC', NULL, 100, true);

INSERT INTO context_rules (context_id, rule_type, role_id, policy_id, required, priority, active) VALUES
('88888888-8888-8888-8888-888888888105', 'RBAC', '33333333-3333-3333-3333-333333333101', NULL, true, 100, true);
