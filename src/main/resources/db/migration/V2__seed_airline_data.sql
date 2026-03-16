-- Airline PSS & DCS Authorization Data
-- Tenant: airline-pss

-- =====================================================
-- RESOURCES
-- =====================================================

INSERT INTO resources (id, tenant_id, name, type, description, active) VALUES
-- PSS Resources
(1, 'airline-pss', 'reservations', 'PSS_MODULE', 'Flight reservations and bookings', true),
(2, 'airline-pss', 'passengers', 'PSS_MODULE', 'Passenger information management', true),
(3, 'airline-pss', 'inventory', 'PSS_MODULE', 'Flight inventory and seat management', true),
(4, 'airline-pss', 'fares', 'PSS_MODULE', 'Fare rules and pricing', true),
(5, 'airline-pss', 'tickets', 'PSS_MODULE', 'Ticket issuance and management', true),

-- DCS Resources
(6, 'airline-pss', 'check-in', 'DCS_MODULE', 'Passenger check-in operations', true),
(7, 'airline-pss', 'boarding', 'DCS_MODULE', 'Boarding pass and gate operations', true),
(8, 'airline-pss', 'baggage', 'DCS_MODULE', 'Baggage handling and tracking', true),
(9, 'airline-pss', 'load-control', 'DCS_MODULE', 'Weight and balance management', true),
(10, 'airline-pss', 'flight-manifest', 'DCS_MODULE', 'Flight manifest and passenger lists', true),

-- Common Resources
(11, 'airline-pss', 'flights', 'COMMON', 'Flight schedules and operations', true),
(12, 'airline-pss', 'reports', 'COMMON', 'Operational reports and analytics', true),
(13, 'airline-pss', 'admin', 'COMMON', 'System administration', true);

-- =====================================================
-- PERMISSIONS (with bit_index for O(1) lookup)
-- =====================================================

INSERT INTO permissions (id, tenant_id, name, action, resource_id, bit_index, description, active) VALUES
-- Reservations (0-9)
(14, 'airline-pss', 'reservations:READ', 'READ', 1, 0, 'View reservations', true),
(15, 'airline-pss', 'reservations:CREATE', 'CREATE', 1, 1, 'Create new reservations', true),
(16, 'airline-pss', 'reservations:UPDATE', 'UPDATE', 1, 2, 'Modify reservations', true),
(17, 'airline-pss', 'reservations:CANCEL', 'CANCEL', 1, 3, 'Cancel reservations', true),

-- Passengers (10-19)
(18, 'airline-pss', 'passengers:READ', 'READ', 2, 10, 'View passenger data', true),
(19, 'airline-pss', 'passengers:UPDATE', 'UPDATE', 2, 11, 'Update passenger info', true),
(20, 'airline-pss', 'passengers:PII_ACCESS', 'PII_ACCESS', 2, 12, 'Access sensitive PII', true),

-- Inventory (20-29)
(21, 'airline-pss', 'inventory:READ', 'READ', 3, 20, 'View inventory', true),
(22, 'airline-pss', 'inventory:UPDATE', 'UPDATE', 3, 21, 'Modify inventory', true),
(23, 'airline-pss', 'inventory:OVERRIDE', 'OVERRIDE', 3, 22, 'Override inventory limits', true),

-- Check-in (30-39)
(24, 'airline-pss', 'check-in:READ', 'READ', 6, 30, 'View check-in status', true),
(25, 'airline-pss', 'check-in:PERFORM', 'PERFORM', 6, 31, 'Perform check-in', true),
(26, 'airline-pss', 'check-in:OVERRIDE', 'OVERRIDE', 6, 32, 'Override check-in rules', true),

-- Boarding (40-49)
(27, 'airline-pss', 'boarding:READ', 'READ', 7, 40, 'View boarding status', true),
(28, 'airline-pss', 'boarding:SCAN', 'SCAN', 7, 41, 'Scan boarding passes', true),
(29, 'airline-pss', 'boarding:CLOSE', 'CLOSE', 7, 42, 'Close boarding', true),

-- Baggage (50-59)
(30, 'airline-pss', 'baggage:READ', 'READ', 8, 50, 'View baggage info', true),
(31, 'airline-pss', 'baggage:TAG', 'TAG', 8, 51, 'Tag baggage', true),
(32, 'airline-pss', 'baggage:TRACK', 'TRACK', 8, 52, 'Track baggage', true),

-- Load Control (60-69)
(33, 'airline-pss', 'load-control:READ', 'READ', 9, 60, 'View load sheets', true),
(34, 'airline-pss', 'load-control:UPDATE', 'UPDATE', 9, 61, 'Update load data', true),
(35, 'airline-pss', 'load-control:FINALIZE', 'FINALIZE', 9, 62, 'Finalize load sheet', true),

-- Admin (90-99)
(36, 'airline-pss', 'admin:FULL_ACCESS', 'FULL_ACCESS', 13, 90, 'Full system access', true);

-- =====================================================
-- ROLES
-- =====================================================

INSERT INTO roles (id, tenant_id, name, description, system_role, hierarchy_depth, active) VALUES
-- PSS Roles
(37, 'airline-pss', 'reservation-agent', 'Handles flight reservations and bookings', false, 0, true),
(38, 'airline-pss', 'ticketing-agent', 'Issues and manages tickets', false, 0, true),
(39, 'airline-pss', 'inventory-manager', 'Manages flight inventory', false, 0, true),

-- DCS Roles
(40, 'airline-pss', 'check-in-agent', 'Performs passenger check-in', false, 0, true),
(41, 'airline-pss', 'gate-agent', 'Handles boarding operations', false, 0, true),
(42, 'airline-pss', 'baggage-handler', 'Manages baggage operations', false, 0, true),
(43, 'airline-pss', 'load-master', 'Manages weight and balance', false, 0, true),

-- Supervisor Roles
(44, 'airline-pss', 'pss-supervisor', 'Supervises PSS operations', false, 1, true),
(45, 'airline-pss', 'dcs-supervisor', 'Supervises DCS operations', false, 1, true),

-- Admin
(46, 'airline-pss', 'system-admin', 'Full system administrator', true, 2, true);

-- =====================================================
-- ROLE-PERMISSION ASSIGNMENTS
-- =====================================================

-- Reservation Agent
INSERT INTO role_permissions (role_id, permission_id) VALUES
(37, 14), -- reservations:READ
(37, 15), -- reservations:CREATE
(37, 16), -- reservations:UPDATE
(37, 18), -- passengers:READ
(37, 19), -- passengers:UPDATE
(37, 21); -- inventory:READ

-- Check-in Agent
INSERT INTO role_permissions (role_id, permission_id) VALUES
(40, 14), -- reservations:READ
(40, 18), -- passengers:READ
(40, 19), -- passengers:UPDATE
(40, 24), -- check-in:READ
(40, 25), -- check-in:PERFORM
(40, 30), -- baggage:READ
(40, 31); -- baggage:TAG

-- Gate Agent
INSERT INTO role_permissions (role_id, permission_id) VALUES
(41, 24), -- check-in:READ
(41, 27), -- boarding:READ
(41, 28), -- boarding:SCAN
(41, 29); -- boarding:CLOSE

-- Load Master
INSERT INTO role_permissions (role_id, permission_id) VALUES
(43, 30), -- baggage:READ
(43, 32), -- baggage:TRACK
(43, 33), -- load-control:READ
(43, 34), -- load-control:UPDATE
(43, 35); -- load-control:FINALIZE

-- DCS Supervisor (inherits + overrides)
INSERT INTO role_permissions (role_id, permission_id) VALUES
(45, 26), -- check-in:OVERRIDE
(45, 20); -- passengers:PII_ACCESS

-- System Admin
INSERT INTO role_permissions (role_id, permission_id) VALUES
(46, 36); -- admin:FULL_ACCESS

-- =====================================================
-- SAMPLE SUBJECTS (Users)
-- =====================================================

INSERT INTO subjects (id, tenant_id, external_id, subject_type, display_name, email, active) VALUES
(47, 'airline-pss', 'agent001', 'USER', 'John Smith', 'john.smith@airline.com', true),
(48, 'airline-pss', 'agent002', 'USER', 'Sarah Johnson', 'sarah.j@airline.com', true),
(49, 'airline-pss', 'gate001', 'USER', 'Mike Chen', 'mike.chen@airline.com', true),
(50, 'airline-pss', 'supervisor001', 'USER', 'Lisa Anderson', 'lisa.a@airline.com', true),
(51, 'airline-pss', 'admin001', 'USER', 'Admin User', 'admin@airline.com', true);

-- =====================================================
-- SUBJECT-ROLE ASSIGNMENTS
-- =====================================================

INSERT INTO subject_roles (subject_id, role_id) VALUES
(47, 37), -- John -> reservation-agent
(48, 40), -- Sarah -> check-in-agent
(49, 41), -- Mike -> gate-agent
(50, 45), -- Lisa -> dcs-supervisor
(51, 46); -- Admin -> system-admin

-- =====================================================
-- SUBJECT ATTRIBUTES (for ABAC)
-- =====================================================

INSERT INTO subject_attributes (subject_id, attribute_name, attribute_value, value_type) VALUES
(47, 'department', 'reservations', 'STRING'),
(47, 'location', 'JFK', 'STRING'),
(47, 'clearance_level', '2', 'INTEGER'),

(48, 'department', 'check-in', 'STRING'),
(48, 'location', 'LAX', 'STRING'),
(48, 'clearance_level', '2', 'INTEGER'),

(49, 'department', 'gate-operations', 'STRING'),
(49, 'location', 'ORD', 'STRING'),
(49, 'clearance_level', '2', 'INTEGER'),

(50, 'department', 'operations', 'STRING'),
(50, 'location', 'LAX', 'STRING'),
(50, 'clearance_level', '3', 'INTEGER'),

(51, 'department', 'IT', 'STRING'),
(51, 'clearance_level', '5', 'INTEGER');
