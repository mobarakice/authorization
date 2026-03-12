# Authorization Service

A high-performance, distributed Authorization Service supporting **RBAC**, **ABAC**, and **Hybrid** access control models with **< 5ms latency** for authorization checks.

[![Java](https://img.shields.io/badge/Java-25-orange)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.0-green)](https://spring.io/projects/spring-boot)
[![GraalVM](https://img.shields.io/badge/GraalVM-Native-blue)](https://www.graalvm.org/)

---

## Table of Contents

- [Project Overview](#project-overview)
- [Access Control Models](#access-control-models)
- [System Architecture](#system-architecture)
- [Entity Diagrams](#entity-diagrams)
- [Flow & Sequence Diagrams](#flow--sequence-diagrams)
- [API Documentation](#api-documentation)
- [Build & Run](#build--run)
- [Docker Deployment](#docker-deployment)

---

## Project Overview

This service provides a centralized, dynamic authorization system designed for microservices architectures. It enables fine-grained access control decisions with ultra-low latency.

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Model Support** | Pure RBAC, pure ABAC, or Hybrid combining both |
| **Sub-5ms Latency** | Optimized with permission bitmaps and two-level caching |
| **Dynamic Configuration** | Roles, policies, and rules configurable at runtime |
| **Multi-Tenancy** | Complete data isolation per tenant |
| **Distributed Caching** | Caffeine L1 + Redis L2 for consistency |
| **Native Image** | GraalVM compilation for instant startup |

### Technology Stack

- **Runtime**: Java 25, GraalVM Native Image
- **Framework**: Spring Boot 4.0
- **Database**: PostgreSQL 16+
- **Caching**: Caffeine (L1), Redis 7 (L2)
- **Messaging**: Apache Kafka
- **APIs**: REST + gRPC

---

## Access Control Models

### RBAC (Role-Based Access Control)

RBAC assigns permissions to roles, and roles to users. It's ideal for hierarchical organizations with well-defined job functions.

```
┌─────────┐      ┌─────────┐      ┌────────────┐
│ Subject │──────│  Role   │──────│ Permission │
│ (User)  │ has  │         │ has  │            │
└─────────┘      └─────────┘      └────────────┘
                      │
                      │ inherits from
                      ▼
                 ┌─────────┐
                 │ Parent  │
                 │  Role   │
                 └─────────┘
```

**When to use RBAC:**

- Organizational role-based permissions (Admin, Manager, User)
- Permission inheritance through role hierarchies
- Simple, predictable access patterns

**Example:**

```
User: john@company.com
Roles: [order-manager]
Permission check: orders:READ → PERMIT (via order-manager role)
```

---

### ABAC (Attribute-Based Access Control)

ABAC evaluates access based on attributes of the subject, resource, action, and environment. It enables context-aware, fine-grained policies.

```
┌──────────────────────────────────────────────────────┐
│                     ABAC Policy                      │
├──────────────────────────────────────────────────────┤
│ IF subject.department = "finance"                    │
│ AND resource.classification = "financial"           │
│ AND action = "READ"                                  │
│ AND environment.time BETWEEN 09:00 AND 18:00        │
│ THEN PERMIT                                          │
└──────────────────────────────────────────────────────┘
```

**Attribute Categories:**

| Category | Examples |
|----------|----------|
| Subject | department, clearance_level, location |
| Resource | type, classification, owner |
| Action | READ, WRITE, DELETE, APPROVE |
| Environment | time, ip_address, device_type |

**When to use ABAC:**

- Context-dependent access (time, location, device)
- Data classification-based access
- Complex business rules beyond role membership

---

### Hybrid Authorization

Hybrid mode combines RBAC and ABAC for maximum flexibility. Multiple combining strategies are supported:

| Strategy | Description |
|----------|-------------|
| `AND` | Both RBAC and ABAC must permit |
| `OR` | Either RBAC or ABAC can permit |
| `RBAC_FIRST` | RBAC permits, then ABAC adds constraints |
| `ABAC_FIRST` | ABAC permits, then RBAC validates |
| `RBAC_REQUIRED_ABAC_CONSTRAINS` | RBAC required, ABAC adds restrictions |
| `ABAC_PRIMARY_RBAC_FALLBACK` | Use ABAC if policies exist, else RBAC |

**Example Hybrid Scenario:**

```
User has "order-manager" role (RBAC: PERMIT)
BUT request is from outside office hours (ABAC: DENY)
Strategy: AND → Final decision: DENY
```

---

## System Architecture

### High-Level Architecture

```
                                ┌─────────────────────────────────┐
                                │         API Gateway             │
                                └──────────────┬──────────────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
            ┌───────────────┐          ┌───────────────┐          ┌───────────────┐
            │  Microservice │          │  Microservice │          │  Microservice │
            │       A       │          │       B       │          │       C       │
            └───────┬───────┘          └───────┬───────┘          └───────┬───────┘
                    │                          │                          │
                    └──────────────────────────┼──────────────────────────┘
                                               │
                                               ▼
                    ┌──────────────────────────────────────────────────────┐
                    │              Authorization Service                    │
                    │  ┌─────────┐  ┌─────────┐  ┌─────────────────────┐ │
                    │  │  REST   │  │  gRPC   │  │ Policy Decision Pt  │ │
                    │  │  :8080  │  │  :9090  │  │       (PDP)         │ │
                    │  └────┬────┘  └────┬────┘  └──────────┬──────────┘ │
                    │       └────────────┴─────────────────┬┘            │
                    │                                      │             │
                    │  ┌───────────┐  ┌───────────┐  ┌─────┴─────┐      │
                    │  │   RBAC    │  │   ABAC    │  │  Hybrid   │      │
                    │  │  Engine   │  │  Engine   │  │  Engine   │      │
                    │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘      │
                    │        └──────────────┴──────────────┘            │
                    │                       │                           │
                    │  ┌────────────────────┴────────────────────┐     │
                    │  │          Two-Level Cache                │     │
                    │  │  ┌─────────────┐  ┌─────────────────┐  │     │
                    │  │  │ Caffeine L1 │  │    Redis L2     │  │     │
                    │  │  │   ~0.1ms    │  │     ~1.0ms      │  │     │
                    │  │  └─────────────┘  └─────────────────┘  │     │
                    │  └─────────────────────────────────────────┘     │
                    └──────────────────────────────────────────────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
            ┌───────────────┐          ┌───────────────┐          ┌───────────────┐
            │  PostgreSQL   │          │     Redis     │          │     Kafka     │
            │   Database    │          │     Cache     │          │    Events     │
            └───────────────┘          └───────────────┘          └───────────────┘
```

### Component Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                      Authorization Service                         │
├────────────────────────────────────────────────────────────────────┤
│  API Layer                                                         │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐  │
│  │ REST Controllers │  │  gRPC Services   │  │  Swagger UI     │  │
│  │ /api/v1/*        │  │  :9090           │  │ /swagger-ui     │  │
│  └────────┬─────────┘  └────────┬─────────┘  └─────────────────┘  │
│           └─────────────────────┴───────────────────┐              │
│                                                     ▼              │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                  Policy Decision Point (PDP)                 │  │
│  │  - Routes to appropriate engine based on mode               │  │
│  │  - Handles correlation IDs and timing                       │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
│                             │                                      │
│  Authorization Engines      │                                      │
│  ┌─────────────────────────┴─────────────────────────┐            │
│  │                                                    │            │
│  ▼                          ▼                         ▼            │
│  ┌──────────┐        ┌──────────┐              ┌───────────┐      │
│  │   RBAC   │        │   ABAC   │              │  Hybrid   │      │
│  │  Engine  │        │  Engine  │              │  Engine   │      │
│  │ (O(1))   │        │ (Policy) │              │(Combined) │      │
│  └────┬─────┘        └────┬─────┘              └─────┬─────┘      │
│       │                   │                          │             │
│       └───────────────────┴──────────────────────────┘             │
│                             │                                      │
│  ┌──────────────────────────┴──────────────────────────────────┐  │
│  │                    Cache Manager                             │  │
│  │  ┌─────────────────────┐  ┌──────────────────────────────┐  │  │
│  │  │ Caffeine L1 (Local) │  │ Redis L2 (Distributed)       │  │  │
│  │  │ - 10K entries       │  │ - Cluster-wide consistency   │  │  │
│  │  │ - 5 min TTL         │  │ - 10 min TTL                 │  │  │
│  │  └─────────────────────┘  └──────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                             │                                      │
│  ┌──────────────────────────┴──────────────────────────────────┐  │
│  │                     Persistence Layer                        │  │
│  │  - JPA Repositories with optimized queries                  │  │
│  │  - Flyway migrations                                        │  │
│  └─────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

---

## Entity Diagrams

### RBAC Entity Model

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│    Resource     │       │   Permission    │       │      Role       │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ id              │       │ id              │       │ id              │
│ tenant_id       │       │ tenant_id       │       │ tenant_id       │
│ name            │◄──────│ resource_id     │       │ name            │
│ type            │   1:N │ name            │  N:M  │ description     │
│ description     │       │ action          │◄──────│ system_role     │
│ metadata        │       │ bit_index ★     │       │ hierarchy_path  │
│ active          │       │ active          │       │ active          │
└─────────────────┘       └─────────────────┘       └────────┬────────┘
                                                             │
                                                             │ N:M
                                                             ▼
                          ┌─────────────────┐       ┌─────────────────┐
                          │ SubjectAttribute│       │    Subject      │
                          ├─────────────────┤       ├─────────────────┤
                          │ id              │       │ id              │
                          │ subject_id      │◄──────│ tenant_id       │
                          │ attribute_name  │   1:N │ external_id     │
                          │ attribute_value │       │ subject_type    │
                          │ value_type      │       │ display_name    │
                          │ valid_from      │       │ active          │
                          │ valid_until     │       └─────────────────┘
                          └─────────────────┘
                          
★ bit_index: Used for O(1) permission bitmap lookup
```

### ABAC Entity Model

```
┌─────────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ AttributeDefinition │       │     Policy      │       │   PolicyRule    │
├─────────────────────┤       ├─────────────────┤       ├─────────────────┤
│ id                  │       │ id              │       │ id              │
│ tenant_id           │       │ tenant_id       │       │ policy_id       │◄─┐
│ name                │       │ name            │       │ name            │  │
│ category            │       │ target_resource │──────►│ condition_logic │  │
│ data_type           │       │ target_action   │   1:N │ order_index     │  │
│ source              │       │ effect          │       │ active          │  │
│ default_value       │       │ priority        │       └────────┬────────┘  │
│ active              │       │ combining_algo  │                │           │
└──────────┬──────────┘       │ active          │                │ 1:N       │
           │                  └─────────────────┘                ▼           │
           │                                            ┌─────────────────┐  │
           │                                            │ RuleCondition   │  │
           │                                            ├─────────────────┤  │
           └───────────────────────────────────────────►│ rule_id         │──┘
                                                   N:1  │ attribute_id    │
                                                        │ operator        │
                                                        │ expected_value  │
                                                        │ negate          │
                                                        └─────────────────┘

Categories: SUBJECT, RESOURCE, ACTION, ENVIRONMENT
Operators: EQUALS, NOT_EQUALS, CONTAINS, IN, BETWEEN, GREATER_THAN, MATCHES_REGEX, etc.
```

### Hybrid Entity Model

```
┌─────────────────────────┐         ┌─────────────────────────┐
│  AuthorizationContext   │         │      ContextRule        │
├─────────────────────────┤         ├─────────────────────────┤
│ id                      │         │ id                      │
│ tenant_id               │         │ context_id              │◄──┐
│ name                    │─────────│ rule_type (RBAC/ABAC)   │   │
│ resource_pattern        │    1:N  │ role_id (FK)            │──►│ Role
│ mode (RBAC/ABAC/HYBRID) │         │ policy_id (FK)          │──►│ Policy
│ combining_strategy      │         │ required                │   │
│ priority                │         │ priority                │   │
│ active                  │         │ active                  │   │
└─────────────────────────┘         └─────────────────────────┘   

Combining Strategies: AND, OR, RBAC_FIRST, ABAC_FIRST, 
                      RBAC_REQUIRED_ABAC_CONSTRAINS, ABAC_PRIMARY_RBAC_FALLBACK
```

---

## Flow & Sequence Diagrams

### Authorization Decision Flow

```
                    ┌──────────────────┐
                    │ Authorization    │
                    │    Request       │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Policy Decision  │
                    │    Point (PDP)   │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Determine Mode   │
                    │ (RBAC/ABAC/      │
                    │  Hybrid)         │
                    └────────┬─────────┘
                             │
             ┌───────────────┼───────────────┐
             │               │               │
             ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │    RBAC     │ │    ABAC     │ │   Hybrid    │
    │   Engine    │ │   Engine    │ │   Engine    │
    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
           │               │               │
           │               │               │
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  Check L1   │ │  Evaluate   │ │  Combine    │
    │  Bitmap     │ │  Policies   │ │  Decisions  │
    │  Cache      │ │  & Rules    │ │             │
    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                           ▼
                    ┌──────────────────┐
                    │ Return Decision  │
                    │ PERMIT/DENY/     │
                    │ NOT_APPLICABLE   │
                    └──────────────────┘
```

### RBAC Authorization Sequence

```
┌────────┐     ┌─────┐     ┌───────────┐     ┌─────────┐     ┌────────┐
│ Client │     │ PDP │     │RbacEngine │     │L1 Cache │     │L2 Redis│
└───┬────┘     └──┬──┘     └─────┬─────┘     └────┬────┘     └───┬────┘
    │             │              │                │              │
    │ authorize() │              │                │              │
    │────────────►│              │                │              │
    │             │ evaluate()   │                │              │
    │             │─────────────►│                │              │
    │             │              │                │              │
    │             │              │ getPermBitmap()│              │
    │             │              │───────────────►│              │
    │             │              │                │              │
    │             │              │    [L1 HIT]    │              │
    │             │              │◄───────────────│              │
    │             │              │                │              │
    │             │              │ ──────────────────────────────│
    │             │              │   [L1 MISS: check L2]         │
    │             │              │───────────────────────────────►
    │             │              │                │              │
    │             │              │◄───────────────────────────────
    │             │              │                │              │
    │             │              │ bitmap.hasPermission(bitIndex)│
    │             │              │ O(1) lookup    │              │
    │             │              │                │              │
    │             │◄─────────────│                │              │
    │◄────────────│ PERMIT/DENY  │                │              │
    │             │              │                │              │
```

### Hybrid Authorization Sequence

```
┌────────┐     ┌─────┐     ┌────────────┐     ┌──────────┐     ┌──────────┐
│ Client │     │ PDP │     │HybridEngine│     │RbacEngine│     │AbacEngine│
└───┬────┘     └──┬──┘     └─────┬──────┘     └────┬─────┘     └────┬─────┘
    │             │              │                 │                │
    │ authorize() │              │                 │                │
    │────────────►│              │                 │                │
    │             │ evaluate()   │                 │                │
    │             │─────────────►│                 │                │
    │             │              │                 │                │
    │             │              │ getStrategy()   │                │
    │             │              │ [e.g., AND]     │                │
    │             │              │                 │                │
    │             │              │ evaluate()      │                │
    │             │              │────────────────►│                │
    │             │              │                 │                │
    │             │              │◄────────────────│                │
    │             │              │ RBAC: PERMIT    │                │
    │             │              │                 │                │
    │             │              │ evaluate()      │                │
    │             │              │─────────────────────────────────►│
    │             │              │                 │                │
    │             │              │◄─────────────────────────────────│
    │             │              │ ABAC: PERMIT    │                │
    │             │              │                 │                │
    │             │              │ combine(AND)    │                │
    │             │              │ PERMIT && PERMIT│                │
    │             │              │ = PERMIT        │                │
    │             │◄─────────────│                 │                │
    │◄────────────│ PERMIT       │                 │                │
```

---

## API Documentation

### Swagger UI

Access interactive API documentation at:

- **Swagger UI**: `http://localhost:8080/swagger-ui.html`
- **OpenAPI Spec**: `http://localhost:8080/v3/api-docs`

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/authorize` | Single authorization check |
| `POST` | `/api/v1/authorize/batch` | Batch authorization check |
| `GET` | `/api/v1/authorize/check` | Simple permission check (query params) |
| `POST` | `/api/v1/authorize/debug` | Authorization with verbose details |
| `GET/POST/PUT/DELETE` | `/api/v1/roles/*` | Role management |
| `GET/POST/PUT/DELETE` | `/api/v1/policies/*` | Policy management |

### Example Authorization Request

```bash
curl -X POST http://localhost:8080/api/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "tenantId": "acme-corp",
    "externalSubjectId": "user-123",
    "resource": "orders",
    "action": "READ",
    "subjectAttributes": {
      "department": "sales"
    }
  }'
```

### Example Response

```json
{
  "decision": "PERMIT",
  "mode": "RBAC",
  "reason": "Permission granted via role assignment",
  "determinedBy": "RBAC Engine",
  "evaluationTimeMs": 1.23,
  "cached": true,
  "cacheLevel": "L1",
  "correlationId": "abc123"
}
```

---

## Build & Run

### Prerequisites

- **Java 25** (GraalVM recommended)
- **Gradle 8.12+**
- **Docker & Docker Compose** (for infrastructure)

### Build Commands

```bash
# Clone the repository
cd /home/technonext/PSS/Authorization

# Initialize Gradle wrapper (first time only)
gradle wrapper --gradle-version 8.12

# Build the project
./gradlew build

# Run tests
./gradlew test

# Build native image (requires GraalVM)
./gradlew nativeCompile
```

### Run Locally

```bash
# 1. Start infrastructure (PostgreSQL, Redis, Kafka)
docker-compose up -d postgres redis kafka

# 2. Run the application
./gradlew bootRun

# 3. Access the application
# REST API: http://localhost:8080
# gRPC: localhost:9090
# Swagger UI: http://localhost:8080/swagger-ui.html
# Health: http://localhost:8080/actuator/health
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | localhost | PostgreSQL host |
| `DB_PORT` | 5432 | PostgreSQL port |
| `DB_NAME` | authorization | Database name |
| `DB_USER` | postgres | Database user |
| `DB_PASSWORD` | postgres | Database password |
| `REDIS_HOST` | localhost | Redis host |
| `REDIS_PORT` | 6379 | Redis port |
| `KAFKA_SERVERS` | localhost:9092 | Kafka bootstrap servers |

---

## Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Start all services (app + infrastructure)
docker-compose up -d

# View logs
docker-compose logs -f authorization-service

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

### Services Started

| Service | Port | Description |
|---------|------|-------------|
| authorization-service | 8080, 9090 | Main application |
| postgres | 5432 | Database |
| redis | 6379 | L2 Cache |
| kafka | 9092 | Event streaming |

### Build and Run with Docker

```bash
# Build the Docker image
docker build -t authorization-service .

# Run with native image
docker run -p 8080:8080 -p 9090:9090 \
  -e DB_HOST=host.docker.internal \
  -e REDIS_HOST=host.docker.internal \
  authorization-service
```

### Production Considerations

1. **Native Image**: Use GraalVM native image for instant startup (~50ms vs ~3s)
2. **Resource Limits**: Set appropriate memory/CPU limits
3. **Health Checks**: Use `/actuator/health` for container orchestration
4. **Monitoring**: Prometheus metrics at `/actuator/prometheus`

---

## License

Apache 2.0

---

## Support

For issues and feature requests, please open an issue in the repository.
