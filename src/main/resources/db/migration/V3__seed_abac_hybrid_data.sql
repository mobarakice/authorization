-- ABAC Policies and Hybrid Authorization for Airline PSS/DCS
-- Tenant: airline-pss

-- =====================================================
-- ATTRIBUTE DEFINITIONS
-- =====================================================

INSERT INTO attribute_definitions (id, tenant_id, name, display_name, category, data_type, source, description, required, active) VALUES
-- Subject Attributes
(52, 'airline-pss', 'department', 'Department', 'SUBJECT', 'STRING', 'USER_PROFILE', 'User department', false, true),
(53, 'airline-pss', 'location', 'Airport Location', 'SUBJECT', 'STRING', 'USER_PROFILE', 'User airport location', false, true),
(54, 'airline-pss', 'clearance_level', 'Security Clearance', 'SUBJECT', 'INTEGER', 'USER_PROFILE', 'Security clearance level', false, true),
(55, 'airline-pss', 'shift', 'Work Shift', 'SUBJECT', 'STRING', 'USER_PROFILE', 'Current work shift', false, true),

-- Resource Attributes
(56, 'airline-pss', 'flight_status', 'Flight Status', 'RESOURCE', 'STRING', 'RESOURCE_METADATA', 'Current flight status', false, true),
(57, 'airline-pss', 'departure_airport', 'Departure Airport', 'RESOURCE', 'STRING', 'RESOURCE_METADATA', 'Flight departure airport', false, true),
(58, 'airline-pss', 'data_classification', 'Data Classification', 'RESOURCE', 'STRING', 'RESOURCE_METADATA', 'Data sensitivity level', false, true),
(59, 'airline-pss', 'booking_class', 'Booking Class', 'RESOURCE', 'STRING', 'RESOURCE_METADATA', 'Fare booking class', false, true),

-- Environment Attributes
(60, 'airline-pss', 'time_of_day', 'Time of Day', 'ENVIRONMENT', 'TIME', 'SYSTEM', 'Current time', false, true),
(61, 'airline-pss', 'ip_address', 'IP Address', 'ENVIRONMENT', 'STRING', 'SYSTEM', 'Request IP address', false, true),
(62, 'airline-pss', 'device_type', 'Device Type', 'ENVIRONMENT', 'STRING', 'SYSTEM', 'Device type (kiosk, mobile, desktop)', false, true);

-- =====================================================
-- ABAC POLICIES
-- =====================================================

-- Policy 1: PII Access - Only during business hours and high clearance
INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, combining_algorithm, version, active) VALUES
(63, 'airline-pss', 'pii-access-policy', 
 'Restrict PII access to business hours and authorized personnel', 
 'passengers', 'PII_ACCESS', 'PERMIT', 100, 'DENY_OVERRIDES', 0, true);

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
(64, 63, 'business-hours-and-clearance', 'AND', 0, true);

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate, order_index) VALUES
(64, 54, 'GREATER_THAN_OR_EQUAL', '3', false, 0),
(64, 60, 'BETWEEN', '08:00', false, 1);

-- Policy 2: Location-based Check-in
INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, combining_algorithm, version, active) VALUES
(65, 'airline-pss', 'location-based-checkin', 
 'Check-in agents can only process flights from their location', 
 'check-in', 'PERFORM', 'PERMIT', 90, 'DENY_OVERRIDES', 0, true);

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
(66, 65, 'same-location-rule', 'AND', 0, true);

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate, order_index) VALUES
(66, 53, 'EQUALS', '${resource.departure_airport}', false, 0);

-- Policy 3: Boarding Close - Only gate agents at departure location
INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, combining_algorithm, version, active) VALUES
(67, 'airline-pss', 'boarding-close-policy', 
 'Only gate agents at departure airport can close boarding', 
 'boarding', 'CLOSE', 'PERMIT', 95, 'DENY_OVERRIDES', 0, true);

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
(68, 67, 'gate-agent-location', 'AND', 0, true);

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate, order_index) VALUES
(68, 52, 'EQUALS', 'gate-operations', false, 0),
(68, 53, 'EQUALS', '${resource.departure_airport}', false, 1);

-- Policy 4: Inventory Override - High clearance only
INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, combining_algorithm, version, active) VALUES
(69, 'airline-pss', 'inventory-override-policy', 
 'Inventory overrides require clearance level 4+', 
 'inventory', 'OVERRIDE', 'PERMIT', 100, 'DENY_OVERRIDES', 0, true);

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
(70, 69, 'high-clearance', 'AND', 0, true);

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate, order_index) VALUES
(70, 54, 'GREATER_THAN_OR_EQUAL', '4', false, 0);

-- Policy 5: Kiosk Restrictions
INSERT INTO policies (id, tenant_id, name, description, target_resource, target_action, effect, priority, combining_algorithm, version, active) VALUES
(71, 'airline-pss', 'kiosk-restriction-policy', 
 'Kiosks have limited access to sensitive operations', 
 'passengers', 'UPDATE', 'DENY', 80, 'DENY_OVERRIDES', 0, true);

INSERT INTO policy_rules (id, policy_id, name, condition_logic, order_index, active) VALUES
(72, 71, 'kiosk-device', 'AND', 0, true);

INSERT INTO rule_conditions (rule_id, attribute_id, operator, expected_value, negate, order_index) VALUES
(72, 62, 'EQUALS', 'kiosk', false, 0),
(72, 58, 'EQUALS', 'sensitive', false, 1);

-- =====================================================
-- HYBRID AUTHORIZATION CONTEXTS
-- =====================================================

-- Context 1: Check-in Operations (Hybrid: RBAC + Location ABAC)
INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
(73, 'airline-pss', 'check-in-context', 
 'Check-in requires role AND location match', 
 'check-in', 'HYBRID', 'AND', 100, true);

INSERT INTO context_rules (context_id, rule_type, role_id, policy_id, required, priority, active) VALUES
(73, 'RBAC', 40, NULL, true, 100, true),
(73, 'ABAC', NULL, 65, true, 90, true);

-- Context 2: Boarding Operations (Hybrid: RBAC + ABAC)
INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
(74, 'airline-pss', 'boarding-context', 
 'Boarding requires gate agent role AND location', 
 'boarding', 'HYBRID', 'AND', 100, true);

INSERT INTO context_rules (context_id, rule_type, role_id, policy_id, required, priority, active) VALUES
(74, 'RBAC', 41, NULL, true, 100, true),
(74, 'ABAC', NULL, 67, true, 95, true);

-- Context 3: PII Access (Hybrid: RBAC OR ABAC with constraints)
INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
(75, 'airline-pss', 'pii-access-context', 
 'PII access requires role with time/clearance constraints', 
 'passengers', 'HYBRID', 'RBAC_REQUIRED_ABAC_CONSTRAINS', 100, true);

INSERT INTO context_rules (context_id, rule_type, role_id, policy_id, required, priority, active) VALUES
(75, 'RBAC', 45, NULL, true, 100, true),
(75, 'ABAC', NULL, 63, true, 100, true);

-- Context 4: Inventory Override (Pure ABAC)
INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
(76, 'airline-pss', 'inventory-override-context', 
 'Inventory overrides use clearance-based ABAC', 
 'inventory', 'ABAC', NULL, 90, true);

INSERT INTO context_rules (context_id, rule_type, role_id, policy_id, required, priority, active) VALUES
(76, 'ABAC', NULL, 69, true, 100, true);

-- Context 5: Reservations (Pure RBAC - simple and fast)
INSERT INTO authorization_contexts (id, tenant_id, name, description, resource_pattern, mode, combining_strategy, priority, active) VALUES
(77, 'airline-pss', 'reservations-context', 
 'Reservations use simple RBAC for speed', 
 'reservations', 'RBAC', NULL, 100, true);

INSERT INTO context_rules (context_id, rule_type, role_id, policy_id, required, priority, active) VALUES
(77, 'RBAC', 37, NULL, true, 100, true);
