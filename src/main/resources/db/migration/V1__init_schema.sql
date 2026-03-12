-- Authorization Service Database Schema
-- PostgreSQL 16+
-- Flyway migration: V1__init_schema.sql

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================
-- RBAC Tables
-- =====================================================

-- Resources table
CREATE TABLE resources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    type VARCHAR(64) NOT NULL,
    description VARCHAR(512),
    metadata JSONB,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uk_resources_tenant_name UNIQUE (tenant_id, name)
);

CREATE INDEX idx_resources_type ON resources(type);
CREATE INDEX idx_resources_tenant_active ON resources(tenant_id, active);

-- Permissions table
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    action VARCHAR(32) NOT NULL,
    resource_id UUID NOT NULL REFERENCES resources(id),
    description VARCHAR(512),
    bit_index INTEGER NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uk_permissions_tenant_name UNIQUE (tenant_id, name),
    CONSTRAINT uk_permissions_tenant_bit_index UNIQUE (tenant_id, bit_index)
);

CREATE INDEX idx_permissions_resource_action ON permissions(resource_id, action);

-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512),
    system_role BOOLEAN NOT NULL DEFAULT false,
    active BOOLEAN NOT NULL DEFAULT true,
    hierarchy_path VARCHAR(1024),
    hierarchy_depth INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uk_roles_tenant_name UNIQUE (tenant_id, name)
);

CREATE INDEX idx_roles_system ON roles(system_role);
CREATE INDEX idx_roles_hierarchy ON roles(tenant_id, hierarchy_path);

-- Role-Permission junction table
CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

-- Role hierarchy table (parent-child relationships)
CREATE TABLE role_hierarchy (
    parent_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    child_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    depth INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (parent_role_id, child_role_id),
    CONSTRAINT chk_no_self_reference CHECK (parent_role_id != child_role_id)
);

-- Subjects table
CREATE TABLE subjects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(64) NOT NULL,
    external_id VARCHAR(256) NOT NULL,
    subject_type VARCHAR(32) NOT NULL DEFAULT 'USER',
    display_name VARCHAR(256),
    email VARCHAR(320),
    active BOOLEAN NOT NULL DEFAULT true,
    last_activity_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uk_subjects_tenant_external UNIQUE (tenant_id, external_id)
);

CREATE INDEX idx_subjects_active ON subjects(tenant_id, active);

-- Subject-Role junction table
CREATE TABLE subject_roles (
    subject_id UUID NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (subject_id, role_id)
);

-- Subject attributes table
CREATE TABLE subject_attributes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id UUID NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    attribute_name VARCHAR(128) NOT NULL,
    attribute_value VARCHAR(2048) NOT NULL,
    value_type VARCHAR(32) NOT NULL DEFAULT 'STRING',
    valid_from TIMESTAMP WITH TIME ZONE,
    valid_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_subject_attr_lookup ON subject_attributes(subject_id, attribute_name);
CREATE INDEX idx_subject_attr_validity ON subject_attributes(subject_id, valid_from, valid_until);

-- =====================================================
-- ABAC Tables
-- =====================================================

-- Attribute definitions table
CREATE TABLE attribute_definitions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    display_name VARCHAR(256),
    description VARCHAR(512),
    category VARCHAR(32) NOT NULL,
    data_type VARCHAR(32) NOT NULL,
    source VARCHAR(32) NOT NULL,
    source_path VARCHAR(256),
    required BOOLEAN NOT NULL DEFAULT false,
    default_value VARCHAR(1024),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uk_attr_def_tenant_name UNIQUE (tenant_id, name)
);

CREATE INDEX idx_attr_def_category ON attribute_definitions(category);

-- Policies table
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(1024),
    target_resource VARCHAR(256) NOT NULL,
    target_action VARCHAR(64) NOT NULL DEFAULT '*',
    effect VARCHAR(16) NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    combining_algorithm VARCHAR(32) NOT NULL DEFAULT 'DENY_OVERRIDES',
    active BOOLEAN NOT NULL DEFAULT true,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uk_policies_tenant_name UNIQUE (tenant_id, name)
);

CREATE INDEX idx_policies_target ON policies(tenant_id, target_resource, target_action);
CREATE INDEX idx_policies_priority ON policies(tenant_id, priority);

-- Policy rules table
CREATE TABLE policy_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512),
    order_index INTEGER NOT NULL DEFAULT 0,
    condition_logic VARCHAR(8) NOT NULL DEFAULT 'AND',
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_policy_rules_policy ON policy_rules(policy_id, order_index);

-- Rule conditions table
CREATE TABLE rule_conditions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID NOT NULL REFERENCES policy_rules(id) ON DELETE CASCADE,
    attribute_id UUID NOT NULL REFERENCES attribute_definitions(id),
    operator VARCHAR(32) NOT NULL,
    expected_value VARCHAR(2048),
    expected_value_2 VARCHAR(2048),
    negate BOOLEAN NOT NULL DEFAULT false,
    order_index INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_rule_conditions_rule ON rule_conditions(rule_id, order_index);

-- =====================================================
-- Hybrid Authorization Tables
-- =====================================================

-- Authorization contexts table
CREATE TABLE authorization_contexts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512),
    resource_pattern VARCHAR(256) NOT NULL,
    mode VARCHAR(16) NOT NULL,
    combining_strategy VARCHAR(32),
    priority INTEGER NOT NULL DEFAULT 100,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uk_auth_ctx_tenant_name UNIQUE (tenant_id, name)
);

CREATE INDEX idx_auth_ctx_resource ON authorization_contexts(tenant_id, resource_pattern);

-- Context rules table
CREATE TABLE context_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    context_id UUID NOT NULL REFERENCES authorization_contexts(id) ON DELETE CASCADE,
    rule_type VARCHAR(16) NOT NULL,
    role_id UUID REFERENCES roles(id),
    policy_id UUID REFERENCES policies(id),
    required BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 100,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_context_rules_ctx ON context_rules(context_id, priority);

-- =====================================================
-- Audit and Change Tracking
-- =====================================================

-- Authorization audit log (for compliance)
CREATE TABLE authorization_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(64) NOT NULL,
    subject_id VARCHAR(256) NOT NULL,
    resource VARCHAR(256) NOT NULL,
    action VARCHAR(64) NOT NULL,
    decision VARCHAR(16) NOT NULL,
    mode VARCHAR(16) NOT NULL,
    determined_by VARCHAR(256),
    evaluation_time_ms DECIMAL(10, 4),
    correlation_id VARCHAR(64),
    request_context JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Partition by month for performance
CREATE INDEX idx_audit_log_tenant_time ON authorization_audit_log(tenant_id, created_at);
CREATE INDEX idx_audit_log_subject ON authorization_audit_log(tenant_id, subject_id, created_at);

-- Policy change history
CREATE TABLE policy_change_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL,
    change_type VARCHAR(16) NOT NULL,
    old_value JSONB,
    new_value JSONB,
    changed_by VARCHAR(256),
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policy_history_policy ON policy_change_history(policy_id, changed_at);
