# Entity Relationship — Authorization Service

> Domain: PSS Authorization — RBAC + ABAC hybrid model
> Maps `example-usecase.md` business concepts to JPA entities and their relationships.

---

## 1. Business Domain Overview

The `example-usecase.md` defines a PSS authorization domain with five resources, four standard actions, five roles, and eight users. This service implements that domain using three layered models:

| Layer | Purpose | Entities |
|---|---|---|
| **RBAC** | Role-based coarse access control | Subject, Role, Permission, Resource, SubjectAttribute |
| **ABAC** | Attribute-based fine-grained control | Policy, PolicyRule, RuleCondition, AttributeDefinition |
| **Hybrid** | Combining strategy orchestration | AuthorizationContext, ContextRule |

All entities share two base classes:

```
BaseEntity
  └── TenantAwareEntity
        ├── Subject
        ├── Role
        ├── Permission
        ├── Resource
        ├── Policy
        ├── AttributeDefinition
        └── AuthorizationContext
```

- **`BaseEntity`** — provides `createdAt` / `updatedAt` (JPA auditing).
- **`TenantAwareEntity`** — adds `tenantId` (multi-tenant isolation; indexed).

---

## 2. RBAC Layer

### Entity Map

```
Subject ──────────────── SubjectAttribute
  │  (1:N, cascade)
  │
  │ N:N (subject_roles)
  ▼
Role ──────────────────── Role (self-join, role_hierarchy)
  │  (N:N, parent/child)
  │
  │ N:N (role_permissions)
  ▼
Permission
  │
  │ N:1
  ▼
Resource
```

### Entity Descriptions

#### `Resource`
Represents a protected entity. Maps to the five resources in the use-case.

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | auto-generated |
| `tenant_id` | VARCHAR(64) | multi-tenant key |
| `name` | VARCHAR(128) | e.g. `flight`, `price`, `pnr`, `pnl`, `sales` |
| `type` | VARCHAR(64) | resource category |
| `description` | VARCHAR(512) | |
| `metadata` | JSONB | extensible metadata |
| `active` | BOOLEAN | soft-delete flag |

**Relationships:** `1:N → Permission` (a resource has many permissions; cascade delete).

---

#### `Permission`
A single `resource:action` grant. Maps to the role-permission matrix in the use-case.

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | auto-generated |
| `tenant_id` | VARCHAR(64) | |
| `name` | VARCHAR(128) | e.g. `flight:READ` |
| `action` | VARCHAR(32) | `CREATE`, `READ`, `UPDATE`, `DELETE`, `BLOCK`, etc. |
| `resource_id` | UUID FK → `resources` | |
| `bit_index` | INT | O(1) bitmap lookup position |
| `active` | BOOLEAN | |

**Use-case mapping (examples):**

| Permission | Resource | Action | Roles that hold it |
|---|---|---|---|
| `flight:READ` | flight | READ | super-admin, admin, support-exec, booking-agent |
| `price:BLOCK` | price | BLOCK | _(none via role — granted only via ABAC)_ |
| `pnr:READ` | pnr | READ | super-admin, booking-agent |
| `pnl:READ` | pnl | READ | super-admin, support-exec |

**Relationships:** `N:1 → Resource`, `N:N → Role` (via `role_permissions`).

---

#### `Role`
A named collection of permissions. Supports hierarchy (parent roles inherit children's permissions).

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id` | VARCHAR(64) | |
| `name` | VARCHAR(128) | e.g. `super-admin`, `admin`, `support-exec` |
| `system_role` | BOOLEAN | protected from deletion |
| `active` | BOOLEAN | |
| `hierarchy_path` | VARCHAR(1024) | materialized path for subtree queries |
| `hierarchy_depth` | INT | depth in hierarchy tree |

**Roles from use-case:**

| Role | Inherits From | Direct Permissions |
|---|---|---|
| `super-admin` | — | All resources × {CREATE, READ, UPDATE, DELETE} |
| `admin` | — | flight, price, sales × {CREATE, READ, UPDATE, DELETE} |
| `support-exec` | — | flight:READ, pnl:READ |
| `booking-agent` | — | flight:READ, pnr × {CREATE, READ, UPDATE, DELETE} |
| `sale-exec` | — | price, sales × {CREATE, READ, UPDATE, DELETE} |

**Relationships:**
- `N:N → Permission` (via `role_permissions`)
- `N:N → Role self-join` (via `role_hierarchy` — `parent_role_id` / `child_role_id`)
- `N:N → Subject` (via `subject_roles`, mapped side)

---

#### `Subject`
A user, service account, or API key. Maps to the eight users in the use-case.

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | internal identity |
| `tenant_id` | VARCHAR(64) | |
| `external_id` | VARCHAR(256) | IdP `sub` claim — unique per tenant |
| `subject_type` | VARCHAR(32) | `USER`, `SERVICE_ACCOUNT`, `API_KEY` |
| `display_name` | VARCHAR(256) | |
| `email` | VARCHAR(320) | |
| `active` | BOOLEAN | |
| `last_activity_at` | TIMESTAMP | |

**Users from use-case:**

| `external_id` | Role | Notes |
|---|---|---|
| `mobarak` | super-admin | no extra permissions |
| `mahtab` | admin | no extra permissions |
| `shamim` | admin | extra: `price:BLOCK` (via ABAC) |
| `alamin` | support-exec | extra: `pnl:BLOCK` (via ABAC) |
| `hasbullah` | support-exec | extra: `price:READ` (via ABAC) |
| `nafi` | booking-agent | no extra permissions |
| `nahian` | sale-exec | extra: `pnr:READ` (via ABAC) |
| `kiron` | sale-exec | no extra permissions |

**Relationships:**
- `N:N → Role` (via `subject_roles`)
- `1:N → SubjectAttribute` (cascade delete)

---

#### `SubjectAttribute`
A key-value attribute attached to a subject, optionally time-bound. These are the ABAC subject-side attributes (e.g. `extra_permissions = "price:BLOCK"`).

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `subject_id` | UUID FK → `subjects` | |
| `attribute_name` | VARCHAR(128) | e.g. `extra_permissions` |
| `attribute_value` | VARCHAR(2048) | e.g. `price:BLOCK` |
| `value_type` | VARCHAR(32) | `STRING`, `NUMBER`, `BOOLEAN`, `LIST`, `DATE` |
| `valid_from` | TIMESTAMP | nullable — open start if null |
| `valid_until` | TIMESTAMP | nullable — no expiry if null |

**`isValid()` logic:** `valid_from ≤ now` AND (`valid_until` is null OR `valid_until > now`).

**Use-case mapping:**

| Subject | attribute\_name | attribute\_value |
|---|---|---|
| shamim | `extra_permissions` | `price:BLOCK` |
| alamin | `extra_permissions` | `pnl:BLOCK` |
| hasbullah | `extra_permissions` | `price:READ` |
| nahian | `extra_permissions` | `pnr:READ` |

**Relationships:** `N:1 → Subject`.

---

## 3. ABAC Layer

### Entity Map

```
Policy
  │
  │ 1:N (cascade)
  ▼
PolicyRule
  │
  │ 1:N (cascade)
  ▼
RuleCondition
  │
  │ N:1
  ▼
AttributeDefinition
```

### Entity Descriptions

#### `AttributeDefinition`
Declares a named attribute and how to resolve it. A shared catalog of attributes that `RuleCondition` references.

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id` | VARCHAR(64) | |
| `name` | VARCHAR(128) | e.g. `extra_permissions` |
| `display_name` | VARCHAR(256) | |
| `category` | ENUM | `SUBJECT`, `RESOURCE`, `ACTION`, `ENVIRONMENT` |
| `data_type` | ENUM | `STRING`, `NUMBER`, `BOOLEAN`, `LIST`, `DATE`, `DATETIME`, `IP_ADDRESS`, `URI` |
| `source` | VARCHAR(32) | `JWT`, `HEADER`, `DATABASE`, `CONTEXT`, `ENVIRONMENT` |
| `source_path` | VARCHAR(256) | JWT claim path, header name, etc. |
| `required` | BOOLEAN | |
| `default_value` | VARCHAR(1024) | |
| `active` | BOOLEAN | |

**Relationships:** `1:N → RuleCondition` (mapped side).

---

#### `Policy`
Top-level ABAC rule targeting a resource + action combination.

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id` | VARCHAR(64) | |
| `name` | VARCHAR(128) | |
| `target_resource` | VARCHAR(256) | supports wildcards: `price`, `price:*`, `*` |
| `target_action` | VARCHAR(64) | supports wildcards: `BLOCK`, `*` |
| `effect` | ENUM | `PERMIT` or `DENY` |
| `priority` | INT | lower = higher precedence |
| `combining_algorithm` | ENUM | how multiple policies combine (see below) |
| `active` | BOOLEAN | |
| `version` | BIGINT | optimistic locking (`@Version`) |

**`CombiningAlgorithm` values:**

| Algorithm | Behaviour |
|---|---|
| `DENY_OVERRIDES` | Any DENY wins over all PERMITs |
| `PERMIT_OVERRIDES` | Any PERMIT wins over all DENYs |
| `FIRST_APPLICABLE` | First matching policy's effect wins |
| `DENY_UNLESS_PERMIT` | Default DENY unless at least one PERMIT matches |
| `PERMIT_UNLESS_DENY` | Default PERMIT unless at least one DENY matches |
| `ONLY_ONE_APPLICABLE` | Exactly one policy may match; else NOT_APPLICABLE |

**Use-case mapping:** The `extra_permissions` policies use `DENY_OVERRIDES` targeting specific `resource:action` pairs (e.g. `target_resource=price`, `target_action=BLOCK`, `effect=PERMIT`).

**Relationships:** `1:N → PolicyRule` (cascade delete, `@OrderBy("orderIndex ASC")`).

---

#### `PolicyRule`
A named group of conditions within a policy. All rules in a policy must match (implicit AND across rules) for the policy effect to fire.

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `policy_id` | UUID FK → `policies` | |
| `name` | VARCHAR(128) | |
| `order_index` | INT | evaluation order |
| `condition_logic` | VARCHAR(8) | `AND` (all conditions must match) or `OR` (any condition must match) |
| `active` | BOOLEAN | inactive rules are skipped |

**Relationships:** `N:1 → Policy`, `1:N → RuleCondition` (cascade delete).

---

#### `RuleCondition`
A single predicate: `attribute operator expectedValue`. The atomic unit of ABAC evaluation.

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `rule_id` | UUID FK → `policy_rules` | |
| `attribute_id` | UUID FK → `attribute_definitions` | |
| `operator` | ENUM | see `ConditionOperator` table below |
| `expected_value` | VARCHAR(2048) | comparison value (JSON for complex types) |
| `expected_value_2` | VARCHAR(2048) | second bound for `BETWEEN` operator |
| `negate` | BOOLEAN | if true, result is flipped |
| `order_index` | INT | evaluation order |

**`ConditionOperator` values:**

| Operator | Example use |
|---|---|
| `EQUALS` | `department = FINANCE` |
| `NOT_EQUALS` | `status ≠ BLOCKED` |
| `CONTAINS` | `extra_permissions contains price:BLOCK` |
| `NOT_CONTAINS` | |
| `STARTS_WITH` | |
| `ENDS_WITH` | |
| `MATCHES_REGEX` | |
| `IN` / `NOT_IN` | |
| `CONTAINS_ALL` / `CONTAINS_ANY` | |
| `IS_NULL` / `IS_NOT_NULL` | |
| `GREATER_THAN` / `LESS_THAN` / etc. | numeric comparisons |
| `BETWEEN` | date range with `expected_value_2` |
| `IP_IN_RANGE` / `IP_IN_CIDR` | network access rules |

**Use-case mapping:** The "extra permissions" feature uses:
```
attribute:  extra_permissions  (SUBJECT / STRING / DATABASE)
operator:   CONTAINS
value:      price:BLOCK        (or pnl:BLOCK, pnr:READ, price:READ)
negate:     false
```

**Relationships:** `N:1 → PolicyRule`, `N:1 → AttributeDefinition`.

---

## 4. Hybrid Layer

### Entity Map

```
AuthorizationContext
  │
  │ 1:N (cascade)
  ▼
ContextRule ──── N:1 ──► Role      (RBAC rules)
           └──── N:1 ──► Policy    (ABAC rules)
```

### Entity Descriptions

#### `AuthorizationContext`
Defines how authorization is performed for a given resource pattern — which engine to use and how to combine results.

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id` | VARCHAR(64) | |
| `name` | VARCHAR(128) | |
| `resource_pattern` | VARCHAR(256) | e.g. `price:*`, `*` |
| `mode` | ENUM | `RBAC`, `ABAC`, or `HYBRID` |
| `combining_strategy` | ENUM | how RBAC + ABAC results combine |
| `priority` | INT | lower = matched first |
| `active` | BOOLEAN | |

**`CombiningStrategy` values:**

| Strategy | Behaviour |
|---|---|
| `RBAC_FIRST` | Evaluate RBAC; short-circuit PERMIT if granted |
| `ABAC_FIRST` | Evaluate ABAC; short-circuit PERMIT if granted |
| `AND` | Both RBAC and ABAC must PERMIT |
| `OR` | Either RBAC or ABAC PERMIT is sufficient |
| `RBAC_REQUIRED_ABAC_CONSTRAINS` | RBAC must PERMIT; ABAC can only deny |
| `ABAC_PRIMARY_RBAC_FALLBACK` | ABAC decides; fall back to RBAC if NOT_APPLICABLE |

**Use-case mapping:** The PSS example uses `ABAC_PRIMARY_RBAC_FALLBACK`:
- Standard role permissions → RBAC path (fallback).
- Extra permissions (shamim's `price:BLOCK`, alamin's `pnl:BLOCK`, etc.) → ABAC primary path.

**Relationships:** `1:N → ContextRule` (cascade delete, `@OrderBy("priority ASC")`).

---

#### `ContextRule`
Links an `AuthorizationContext` to either a `Role` (RBAC rule) or a `Policy` (ABAC rule).

| DB Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `context_id` | UUID FK → `authorization_contexts` | |
| `rule_type` | VARCHAR(16) | `RBAC` or `ABAC` |
| `role_id` | UUID FK → `roles` | nullable; set when `rule_type=RBAC` |
| `policy_id` | UUID FK → `policies` | nullable; set when `rule_type=ABAC` |
| `required` | BOOLEAN | if true, this rule must match |
| `priority` | INT | evaluation order |
| `active` | BOOLEAN | |

**Relationships:** `N:1 → AuthorizationContext`, `N:1 → Role`, `N:1 → Policy`.

---

## 5. Full Relationship Table

| Entity | → | Entity | Type | Join Table / FK | Notes |
|---|---|---|---|---|---|
| Subject | → | Role | N:N | `subject_roles` | user's assigned roles |
| Subject | → | SubjectAttribute | 1:N | FK `subject_id` | extra ABAC attributes; cascade delete |
| Role | → | Permission | N:N | `role_permissions` | direct permission grants |
| Role | → | Role | N:N (self) | `role_hierarchy` | parent/child inheritance |
| Permission | → | Resource | N:1 | FK `resource_id` | each permission belongs to one resource |
| Resource | → | Permission | 1:N | FK `resource_id` | cascade delete |
| Policy | → | PolicyRule | 1:N | FK `policy_id` | ordered by `order_index`; cascade delete |
| PolicyRule | → | RuleCondition | 1:N | FK `rule_id` | ordered by `order_index`; cascade delete |
| RuleCondition | → | AttributeDefinition | N:1 | FK `attribute_id` | shared attribute catalog |
| AuthorizationContext | → | ContextRule | 1:N | FK `context_id` | ordered by `priority`; cascade delete |
| ContextRule | → | Role | N:1 | FK `role_id` | nullable; RBAC-type rules only |
| ContextRule | → | Policy | N:1 | FK `policy_id` | nullable; ABAC-type rules only |

---

## 6. Authorization Decision Flow

```
POST /api/v1/authorize
        │
        ▼
AuthorizationService
  ├── load Subject by (tenantId, externalSubjectId)
  ├── load SubjectAttributes → filter by isValid()
  ├── merge into AuthorizationRequest.subjectAttributes (putIfAbsent)
  └── delegate to PolicyDecisionPoint (PDP)
              │
              ▼
        HybridEngine           ← looks up AuthorizationContext by resource
          ├── CombiningStrategy = ABAC_PRIMARY_RBAC_FALLBACK
          │
          ├── AbacEngine
          │     ├── PolicyRepository.findApplicablePolicies(tenant, resource, action)
          │     ├── for each Policy → evaluate PolicyRules
          │     │     └── for each RuleCondition
          │     │           └── resolve attribute from SubjectAttributes
          │     │               apply ConditionOperator + negate
          │     └── apply CombiningAlgorithm → PERMIT / DENY / NOT_APPLICABLE
          │
          └── RbacEngine  (fallback if ABAC = NOT_APPLICABLE)
                ├── SubjectRepository.findByExternalIdWithRolesAndPermissions
                ├── Subject.getAllPermissions() → includes inherited via Role hierarchy
                └── PermissionBitmap.hasPermission(resource, action)
```

---

## 7. Key Design Patterns

| Pattern | Where used | Why |
|---|---|---|
| **Materialized path** | `Role.hierarchyPath` | O(log n) ancestor/descendant queries without recursive CTEs |
| **Permission bitmap** | `Permission.bitIndex` | O(1) permission check via bitwise AND |
| **Soft delete** | `active` column on all entities | Preserves audit history; never hard-delete permissions or roles |
| **Optimistic locking** | `Policy.version` | Prevents lost-update on concurrent policy edits |
| **`putIfAbsent` enrichment** | `AuthorizationService` | Caller-supplied attributes always win over DB-loaded ones |
| **Temporal validity** | `SubjectAttribute.validFrom/validUntil` | Time-bound extra permissions (e.g. temporary BLOCK grants) |
| **Multi-tenancy** | `tenantId` on every entity | Complete data isolation between PSS tenants |
| **Lazy loading + custom JPQL** | All `@ManyToMany` / `@OneToMany` | N+1 prevention via explicit `JOIN FETCH` repository queries |
