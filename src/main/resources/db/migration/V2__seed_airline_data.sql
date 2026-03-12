-- Airline PSS & DCS Authorization Data
-- Tenant: airline-pss

-- =====================================================
-- RESOURCES
-- =====================================================

INSERT INTO resources (id, tenant_id, name, type, description, active) VALUES
-- PSS Resources
('11111111-1111-1111-1111-111111111101', 'airline-pss', 'reservations', 'PSS_MODULE', 'Flight reservations and bookings', true),
('11111111-1111-1111-1111-111111111102', 'airline-pss', 'passengers', 'PSS_MODULE', 'Passenger information management', true),
('11111111-1111-1111-1111-111111111103', 'airline-pss', 'inventory', 'PSS_MODULE', 'Flight inventory and seat management', true),
('11111111-1111-1111-1111-111111111104', 'airline-pss', 'fares', 'PSS_MODULE', 'Fare rules and pricing', true),
('11111111-1111-1111-1111-111111111105', 'airline-pss', 'tickets', 'PSS_MODULE', 'Ticket issuance and management', true),

-- DCS Resources
('11111111-1111-1111-1111-111111111201', 'airline-pss', 'check-in', 'DCS_MODULE', 'Passenger check-in operations', true),
('11111111-1111-1111-1111-111111111202', 'airline-pss', 'boarding', 'DCS_MODULE', 'Boarding pass and gate operations', true),
('11111111-1111-1111-1111-111111111203', 'airline-pss', 'baggage', 'DCS_MODULE', 'Baggage handling and tracking', true),
('11111111-1111-1111-1111-111111111204', 'airline-pss', 'load-control', 'DCS_MODULE', 'Weight and balance management', true),
('11111111-1111-1111-1111-111111111205', 'airline-pss', 'flight-manifest', 'DCS_MODULE', 'Flight manifest and passenger lists', true),

-- Common Resources
('11111111-1111-1111-1111-111111111301', 'airline-pss', 'flights', 'COMMON', 'Flight schedules and operations', true),
('11111111-1111-1111-1111-111111111302', 'airline-pss', 'reports', 'COMMON', 'Operational reports and analytics', true),
('11111111-1111-1111-1111-111111111303', 'airline-pss', 'admin', 'COMMON', 'System administration', true);

-- =====================================================
-- PERMISSIONS (with bit_index for O(1) lookup)
-- =====================================================

INSERT INTO permissions (id, tenant_id, name, action, resource_id, bit_index, description, active) VALUES
-- Reservations (0-9)
('22222222-2222-2222-2222-222222222101', 'airline-pss', 'reservations:READ', 'READ', '11111111-1111-1111-1111-111111111101', 0, 'View reservations', true),
('22222222-2222-2222-2222-222222222102', 'airline-pss', 'reservations:CREATE', 'CREATE', '11111111-1111-1111-1111-111111111101', 1, 'Create new reservations', true),
('22222222-2222-2222-2222-222222222103', 'airline-pss', 'reservations:UPDATE', 'UPDATE', '11111111-1111-1111-1111-111111111101', 2, 'Modify reservations', true),
('22222222-2222-2222-2222-222222222104', 'airline-pss', 'reservations:CANCEL', 'CANCEL', '11111111-1111-1111-1111-111111111101', 3, 'Cancel reservations', true),

-- Passengers (10-19)
('22222222-2222-2222-2222-222222222201', 'airline-pss', 'passengers:READ', 'READ', '11111111-1111-1111-1111-111111111102', 10, 'View passenger data', true),
('22222222-2222-2222-2222-222222222202', 'airline-pss', 'passengers:UPDATE', 'UPDATE', '11111111-1111-1111-1111-111111111102', 11, 'Update passenger info', true),
('22222222-2222-2222-2222-222222222203', 'airline-pss', 'passengers:PII_ACCESS', 'PII_ACCESS', '11111111-1111-1111-1111-111111111102', 12, 'Access sensitive PII', true),

-- Inventory (20-29)
('22222222-2222-2222-2222-222222222301', 'airline-pss', 'inventory:READ', 'READ', '11111111-1111-1111-1111-111111111103', 20, 'View inventory', true),
('22222222-2222-2222-2222-222222222302', 'airline-pss', 'inventory:UPDATE', 'UPDATE', '11111111-1111-1111-1111-111111111103', 21, 'Modify inventory', true),
('22222222-2222-2222-2222-222222222303', 'airline-pss', 'inventory:OVERRIDE', 'OVERRIDE', '11111111-1111-1111-1111-111111111103', 22, 'Override inventory limits', true),

-- Check-in (30-39)
('22222222-2222-2222-2222-222222222401', 'airline-pss', 'check-in:READ', 'READ', '11111111-1111-1111-1111-111111111201', 30, 'View check-in status', true),
('22222222-2222-2222-2222-222222222402', 'airline-pss', 'check-in:PERFORM', 'PERFORM', '11111111-1111-1111-1111-111111111201', 31, 'Perform check-in', true),
('22222222-2222-2222-2222-222222222403', 'airline-pss', 'check-in:OVERRIDE', 'OVERRIDE', '11111111-1111-1111-1111-111111111201', 32, 'Override check-in rules', true),

-- Boarding (40-49)
('22222222-2222-2222-2222-222222222501', 'airline-pss', 'boarding:READ', 'READ', '11111111-1111-1111-1111-111111111202', 40, 'View boarding status', true),
('22222222-2222-2222-2222-222222222502', 'airline-pss', 'boarding:SCAN', 'SCAN', '11111111-1111-1111-1111-111111111202', 41, 'Scan boarding passes', true),
('22222222-2222-2222-2222-222222222503', 'airline-pss', 'boarding:CLOSE', 'CLOSE', '11111111-1111-1111-1111-111111111202', 42, 'Close boarding', true),

-- Baggage (50-59)
('22222222-2222-2222-2222-222222222601', 'airline-pss', 'baggage:READ', 'READ', '11111111-1111-1111-1111-111111111203', 50, 'View baggage info', true),
('22222222-2222-2222-2222-222222222602', 'airline-pss', 'baggage:TAG', 'TAG', '11111111-1111-1111-1111-111111111203', 51, 'Tag baggage', true),
('22222222-2222-2222-2222-222222222603', 'airline-pss', 'baggage:TRACK', 'TRACK', '11111111-1111-1111-1111-111111111203', 52, 'Track baggage', true),

-- Load Control (60-69)
('22222222-2222-2222-2222-222222222701', 'airline-pss', 'load-control:READ', 'READ', '11111111-1111-1111-1111-111111111204', 60, 'View load sheets', true),
('22222222-2222-2222-2222-222222222702', 'airline-pss', 'load-control:UPDATE', 'UPDATE', '11111111-1111-1111-1111-111111111204', 61, 'Update load data', true),
('22222222-2222-2222-2222-222222222703', 'airline-pss', 'load-control:FINALIZE', 'FINALIZE', '11111111-1111-1111-1111-111111111204', 62, 'Finalize load sheet', true),

-- Admin (90-99)
('22222222-2222-2222-2222-222222222901', 'airline-pss', 'admin:FULL_ACCESS', 'FULL_ACCESS', '11111111-1111-1111-1111-111111111303', 90, 'Full system access', true);

-- =====================================================
-- ROLES
-- =====================================================

INSERT INTO roles (id, tenant_id, name, description, system_role, hierarchy_depth, active) VALUES
-- PSS Roles
('33333333-3333-3333-3333-333333333101', 'airline-pss', 'reservation-agent', 'Handles flight reservations and bookings', false, 0, true),
('33333333-3333-3333-3333-333333333102', 'airline-pss', 'ticketing-agent', 'Issues and manages tickets', false, 0, true),
('33333333-3333-3333-3333-333333333103', 'airline-pss', 'inventory-manager', 'Manages flight inventory', false, 0, true),

-- DCS Roles
('33333333-3333-3333-3333-333333333201', 'airline-pss', 'check-in-agent', 'Performs passenger check-in', false, 0, true),
('33333333-3333-3333-3333-333333333202', 'airline-pss', 'gate-agent', 'Handles boarding operations', false, 0, true),
('33333333-3333-3333-3333-333333333203', 'airline-pss', 'baggage-handler', 'Manages baggage operations', false, 0, true),
('33333333-3333-3333-3333-333333333204', 'airline-pss', 'load-master', 'Manages weight and balance', false, 0, true),

-- Supervisor Roles
('33333333-3333-3333-3333-333333333301', 'airline-pss', 'pss-supervisor', 'Supervises PSS operations', false, 1, true),
('33333333-3333-3333-3333-333333333302', 'airline-pss', 'dcs-supervisor', 'Supervises DCS operations', false, 1, true),

-- Admin
('33333333-3333-3333-3333-333333333401', 'airline-pss', 'system-admin', 'Full system administrator', true, 2, true);

-- =====================================================
-- ROLE-PERMISSION ASSIGNMENTS
-- =====================================================

-- Reservation Agent
INSERT INTO role_permissions (role_id, permission_id) VALUES
('33333333-3333-3333-3333-333333333101', '22222222-2222-2222-2222-222222222101'), -- reservations:READ
('33333333-3333-3333-3333-333333333101', '22222222-2222-2222-2222-222222222102'), -- reservations:CREATE
('33333333-3333-3333-3333-333333333101', '22222222-2222-2222-2222-222222222103'), -- reservations:UPDATE
('33333333-3333-3333-3333-333333333101', '22222222-2222-2222-2222-222222222201'), -- passengers:READ
('33333333-3333-3333-3333-333333333101', '22222222-2222-2222-2222-222222222202'), -- passengers:UPDATE
('33333333-3333-3333-3333-333333333101', '22222222-2222-2222-2222-222222222301'); -- inventory:READ

-- Check-in Agent
INSERT INTO role_permissions (role_id, permission_id) VALUES
('33333333-3333-3333-3333-333333333201', '22222222-2222-2222-2222-222222222101'), -- reservations:READ
('33333333-3333-3333-3333-333333333201', '22222222-2222-2222-2222-222222222201'), -- passengers:READ
('33333333-3333-3333-3333-333333333201', '22222222-2222-2222-2222-222222222202'), -- passengers:UPDATE
('33333333-3333-3333-3333-333333333201', '22222222-2222-2222-2222-222222222401'), -- check-in:READ
('33333333-3333-3333-3333-333333333201', '22222222-2222-2222-2222-222222222402'), -- check-in:PERFORM
('33333333-3333-3333-3333-333333333201', '22222222-2222-2222-2222-222222222601'), -- baggage:READ
('33333333-3333-3333-3333-333333333201', '22222222-2222-2222-2222-222222222602'); -- baggage:TAG

-- Gate Agent
INSERT INTO role_permissions (role_id, permission_id) VALUES
('33333333-3333-3333-3333-333333333202', '22222222-2222-2222-2222-222222222401'), -- check-in:READ
('33333333-3333-3333-3333-333333333202', '22222222-2222-2222-2222-222222222501'), -- boarding:READ
('33333333-3333-3333-3333-333333333202', '22222222-2222-2222-2222-222222222502'), -- boarding:SCAN
('33333333-3333-3333-3333-333333333202', '22222222-2222-2222-2222-222222222503'); -- boarding:CLOSE

-- Load Master
INSERT INTO role_permissions (role_id, permission_id) VALUES
('33333333-3333-3333-3333-333333333204', '22222222-2222-2222-2222-222222222601'), -- baggage:READ
('33333333-3333-3333-3333-333333333204', '22222222-2222-2222-2222-222222222603'), -- baggage:TRACK
('33333333-3333-3333-3333-333333333204', '22222222-2222-2222-2222-222222222701'), -- load-control:READ
('33333333-3333-3333-3333-333333333204', '22222222-2222-2222-2222-222222222702'), -- load-control:UPDATE
('33333333-3333-3333-3333-333333333204', '22222222-2222-2222-2222-222222222703'); -- load-control:FINALIZE

-- DCS Supervisor (inherits + overrides)
INSERT INTO role_permissions (role_id, permission_id) VALUES
('33333333-3333-3333-3333-333333333302', '22222222-2222-2222-2222-222222222403'), -- check-in:OVERRIDE
('33333333-3333-3333-3333-333333333302', '22222222-2222-2222-2222-222222222203'); -- passengers:PII_ACCESS

-- System Admin
INSERT INTO role_permissions (role_id, permission_id) VALUES
('33333333-3333-3333-3333-333333333401', '22222222-2222-2222-2222-222222222901'); -- admin:FULL_ACCESS

-- =====================================================
-- SAMPLE SUBJECTS (Users)
-- =====================================================

INSERT INTO subjects (id, tenant_id, external_id, subject_type, display_name, email, active) VALUES
('44444444-4444-4444-4444-444444444101', 'airline-pss', 'agent001', 'USER', 'John Smith', 'john.smith@airline.com', true),
('44444444-4444-4444-4444-444444444102', 'airline-pss', 'agent002', 'USER', 'Sarah Johnson', 'sarah.j@airline.com', true),
('44444444-4444-4444-4444-444444444103', 'airline-pss', 'gate001', 'USER', 'Mike Chen', 'mike.chen@airline.com', true),
('44444444-4444-4444-4444-444444444104', 'airline-pss', 'supervisor001', 'USER', 'Lisa Anderson', 'lisa.a@airline.com', true),
('44444444-4444-4444-4444-444444444105', 'airline-pss', 'admin001', 'USER', 'Admin User', 'admin@airline.com', true);

-- =====================================================
-- SUBJECT-ROLE ASSIGNMENTS
-- =====================================================

INSERT INTO subject_roles (subject_id, role_id) VALUES
('44444444-4444-4444-4444-444444444101', '33333333-3333-3333-3333-333333333101'), -- John -> reservation-agent
('44444444-4444-4444-4444-444444444102', '33333333-3333-3333-3333-333333333201'), -- Sarah -> check-in-agent
('44444444-4444-4444-4444-444444444103', '33333333-3333-3333-3333-333333333202'), -- Mike -> gate-agent
('44444444-4444-4444-4444-444444444104', '33333333-3333-3333-3333-333333333302'), -- Lisa -> dcs-supervisor
('44444444-4444-4444-4444-444444444105', '33333333-3333-3333-3333-333333333401'); -- Admin -> system-admin

-- =====================================================
-- SUBJECT ATTRIBUTES (for ABAC)
-- =====================================================

INSERT INTO subject_attributes (subject_id, attribute_name, attribute_value, value_type) VALUES
('44444444-4444-4444-4444-444444444101', 'department', 'reservations', 'STRING'),
('44444444-4444-4444-4444-444444444101', 'location', 'JFK', 'STRING'),
('44444444-4444-4444-4444-444444444101', 'clearance_level', '2', 'INTEGER'),

('44444444-4444-4444-4444-444444444102', 'department', 'check-in', 'STRING'),
('44444444-4444-4444-4444-444444444102', 'location', 'LAX', 'STRING'),
('44444444-4444-4444-4444-444444444102', 'clearance_level', '2', 'INTEGER'),

('44444444-4444-4444-4444-444444444103', 'department', 'gate-operations', 'STRING'),
('44444444-4444-4444-4444-444444444103', 'location', 'ORD', 'STRING'),
('44444444-4444-4444-4444-444444444103', 'clearance_level', '2', 'INTEGER'),

('44444444-4444-4444-4444-444444444104', 'department', 'operations', 'STRING'),
('44444444-4444-4444-4444-444444444104', 'location', 'LAX', 'STRING'),
('44444444-4444-4444-4444-444444444104', 'clearance_level', '3', 'INTEGER'),

('44444444-4444-4444-4444-444444444105', 'department', 'IT', 'STRING'),
('44444444-4444-4444-4444-444444444105', 'clearance_level', '5', 'INTEGER');
