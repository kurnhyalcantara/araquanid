# Architecture

This service follows a **feature-based Clean Architecture** with DDD-inspired
domain modeling. The codebase is organized **by feature, not by responsibility**:
each capability owns its full vertical slice (delivery, repository, usecase)
under `internal/features/<name>/`, while `domain` and `validator` stay shared,
flat, top-level packages since entities and validation conventions are
cross-cutting. It is **gRPC-first**: the proto contract is the source of truth
— it lives in the centralized [`probopass`](https://github.com/kurnhyalcantara/probopass)
contract repo and this service consumes the generated Go stubs as a module
dependency — and REST is derived from it via grpc-gateway. This document is
the blueprint for every service built from this template. The `example` CRUD
slice under `internal/features/example/` is the reference implementation
every new capability should mirror.

## Layers

```
            ┌──────────────────────────────────────────────────┐
 inbound →  │ delivery/{grpc,rest}  ← transport types           │
            ├──────────────────────────────────────────────────┤
            │ usecase  ← application logic, ports               │
            ├──────────────────────────────────────────────────┤
            │ domain   ← entities, invariants (pure, shared)    │
            ├──────────────────────────────────────────────────┤
 outbound → │ repository/{db,redis,kafka} ← adapters             │
            └──────────────────────────────────────────────────┘
      per-feature: delivery, repository, usecase (internal/features/<name>/)
      shared:      domain, validator (internal/)
      platform = infra init   container = wiring
```

| Layer | Location | Responsibility |
|---|---|---|
| Domain | `internal/domain` | Shared, pure entities, value objects, invariants, domain errors — one file per feature (e.g. `example.go`) |
| Feature | `internal/features/<name>/` | One vertical slice per capability: `delivery`, `repository`, `usecase` |
| ↳ Usecase | `internal/features/<name>/usecase` | Application logic; depends only on domain + repository ports |
| ↳ Repository | `internal/features/<name>/repository` | Outbound port (interface) + per-store adapter subpackages (`db/`, `redis/`, `kafka/`, created as needed) |
| ↳ Delivery | `internal/features/<name>/delivery/{grpc,rest}` (+ `grpc/dto`, `grpc/mapper`) | Inbound adapters: gRPC server impl + REST gateway registration; dtos and mappers live under `grpc/` since they're proto-shaped |
| Validator | `internal/validator` | Shared, flat package. Generic engine in `validator.go`; per-feature check methods in their own file (e.g. `example.go`) |
| Platform | `pkg/platform/*` (in `kingler`) | Infrastructure **initialization only** (clients, servers) |
| Container | `container/` | Composition root: `Build` wires the whole graph, `Close` tears it down |
| Shared | `kingler/pkg/*` | Cross-cutting concerns (`apperror`, `ctxutil`, `middleware`, `pagination`, …) |

## Dependency rules

Enforced by `depguard` in `.golangci.yml` — violations fail `make lint` and CI.

1. **Domain is pure.** `internal/domain/**` imports stdlib and other domain
   packages only. Never transport (the probopass proto stubs, grpc),
   infrastructure (`platform/`, drivers), or any feature's delivery layer.
2. **Usecases see ports, not adapters.** A usecase (`internal/features/<name>/usecase`)
   imports `internal/domain`, its own feature's `repository` *interface*, and
   shared `kingler/pkg/*` helpers. It must not import the probopass proto
   stubs, `platform/`, drivers, or its feature's `delivery/**` (including
   `delivery/grpc/dto` and `delivery/grpc/mapper`). When a usecase needs a
   platform capability, it defines a small interface where it is consumed and
   the container injects the platform implementation. Each feature added to
   `.golangci.yml`'s `usecase-clean` deny list needs its own
   `internal/features/<name>/delivery` entry (depguard `pkg` matches by
   prefix, so one line covers both `grpc` and `rest` subpackages).
3. **Transport types stop at the mapper.** Only a feature's `delivery/grpc`
   and `delivery/grpc/mapper` may import the probopass proto stubs. Proto
   messages never reach usecases or the domain.
4. **Platform contains no business logic.** `platform/**` may import third-party
   libraries, never `internal/` or `container/`.
5. **The container imports everything; nothing imports the container** (except `cmd/`).

## Repository definition

A repository is an **outbound adapter abstraction** — the port through which a
usecase reaches anything outside the process:

- PostgreSQL, Redis
- other gRPC/HTTP services
- third-party APIs
- message brokers (Kafka)

It is *not* limited to database access. The interface lives in
`internal/features/<name>/repository/repository.go`, named for the capability
it provides, and is consumed by the usecase. Each backing store gets its own
adapter subpackage — `repository/db` (SQL), `repository/redis` (cache/pubsub),
`repository/kafka` (producer/consumer) — created only when the feature
actually needs that store. Adapters implement the parent package's interface
and can be composed — see `redis.NewCache`, a read-through cache decorator
that wraps `db.NewPostgres` while the usecase still sees a single
`repository.Repository`.

Since `db`, `redis`, and `kafka` are separate Go packages, a common
third-party import (e.g. `github.com/redis/go-redis/v9`, itself named `redis`)
is aliased (`redislib`) to avoid colliding with the adapter package's own name
— see `repository/redis/cache.go`.

## Package structure

```
internal/
├── domain/                       # shared, pure entities/invariants — one file per feature
│   └── example.go
├── features/
│   └── example/                  # one vertical slice per capability
│       ├── delivery/
│       │   ├── grpc/
│       │   │   ├── handler.go    # implements the generated *ServiceServer; thin: validate → map → usecase → map
│       │   │   ├── dto/          # handler input structs (with `validate` tags)
│       │   │   └── mapper/       # pure functions: proto ⇄ dto ⇄ domain/usecase types
│       │   └── rest/
│       │       └── rest.go       # registers the grpc-gateway translation onto the shared mux
│       ├── repository/
│       │   ├── repository.go     # outbound port (interface)
│       │   ├── db/                # SQL adapter (postgres.go, ...)
│       │   └── redis/             # cache/pubsub adapter (cache.go, ...)
│       └── usecase/               # interface + implementation; application logic (+ tests against a fake repo)
└── validator/                     # shared, flat — converts validation failures into apperror.CodeInvalidArgument
    ├── validator.go               # generic engine (Validator, New, check)
    └── example.go                 # per-feature check methods
```

Usecase methods take primitive/domain inputs and return domain or usecase-owned
types (e.g. `usecase.ExampleList`); the `dto` package is a delivery concern, so
the usecase never depends on it.

## Dependency injection strategy

Manual constructor wiring — no DI framework, no codegen, no reflection.

- `container`: `Build(ctx, cfg)` is the single composition root. It calls the
  platform and per-feature usecase/delivery constructors directly — config →
  platform → repositories → usecases → handlers → middleware → servers, in
  that order — making composition decisions inline (e.g. wrapping the
  Postgres repository in the Redis cache) with a comment, and registers each
  feature's handler on the gRPC server and gateway mux. `Close(ctx)` releases
  resources in reverse. There is no separate provider or registry layer.
  `cmd/server` is a cobra CLI; its `serve` command loads config, calls
  `container.Build`, and runs the servers.
- Platform constructors take a single `Config` struct (the source of truth), not
  functional options — e.g. `postgres.New(ctx, postgres.Config{DSN: …})`.
- Import aliases: since every feature has a `repository`, `db`, `redis`, and
  `delivery/grpc`/`delivery/rest` package with the same base name, `container.go`
  aliases each feature's imports with the feature name as prefix (`exampledb`,
  `exampleredis`, `exampleusecase`, `examplegrpc`, `examplerest`).

## Error handling

- Usecases and repositories return `*apperror.Error`
  (`pkg/apperror`) with a transport-agnostic code; wrapped causes
  are logged but never sent to clients.
- The `middleware.AppError` interceptor maps codes to gRPC statuses; the
  gateway error handler (`middleware.GatewayOptions`) maps those to HTTP with a
  `{"code","message"}` JSON body.
- Repositories translate driver errors to domain errors (`pgx.ErrNoRows` →
  `domain.ErrNotFound`); usecases translate domain errors to apperrors.

## Observability

- **Tracing**: OTel via the otelgrpc stats handler on server and loopback
  client; OTLP export is config-gated (`telemetry.enabled`).
- **Metrics**: OTel Prometheus exporter + Go runtime collectors, scraped from
  `/metrics` on the ops port.
- **Logs**: `slog`, JSON in production; every record is enriched with
  `trace_id`/`span_id` from the context, and every RPC gets one log line with
  method, code, duration, and request id.
- **Health**: gRPC health service; `/healthz` (liveness) and `/readyz`
  (pings Postgres/Redis) on the ops port.

## Naming conventions

- Packages: short, lowercase, singular (`example`, not `examples`).
- Feature layer files: `delivery/grpc/handler.go`, `usecase/usecase.go`,
  `repository/repository.go` (interface), `repository/db/postgres.go`,
  `repository/redis/cache.go`, `delivery/grpc/dto/dto.go`,
  `delivery/grpc/mapper/mapper.go`.
- Shared package files: `validator/validator.go` (engine) +
  `validator/<feature>.go` (per-feature checks); `domain/<feature>.go`.
- Interfaces are named for the role (`Repository`, `Usecase`); implementations
  are unexported (`postgresRepository`) and returned from constructors
  (`NewPostgres`). Constructors in adapter subpackages drop the store name if
  it's redundant with the package name (`redis.NewCache`, not
  `redis.NewRedisCache`).
- Protos (in the probopass repo): `proto/probopass/{service}/v1/{service}.proto`,
  package `probopass.{service}.v1`, verb-first RPCs (`CreateExample`), one
  dedicated response message per RPC.
- Migrations: `NNNNNN_description.{up,down}.sql`.
- Env vars: `ARAQUANID_` prefix, `__` separates nesting (`ARAQUANID_POSTGRES__HOST`).

## Adding or changing a capability (recipe)

1. **Contract**: in the [`probopass`](https://github.com/kurnhyalcantara/probopass)
   repo, add/extend `proto/probopass/{service}/v1/{service}.proto` with HTTP
   annotations, run `buf generate`, and release it; then `make proto-update`
   here to pull the generated stubs.
2. **Domain**: add the entity, invariants, and errors as a new file in the
   shared `internal/domain` package.
3. **Migration**: `make migrate-create NAME=create_{name}s`.
4. **Feature scaffold**: create `internal/features/<name>/` following the
   `example` slice's shape — `repository` (interface + `db`/`redis`/`kafka`
   adapters as needed) → `usecase` (+ tests against a fake repository) →
   `delivery/grpc/dto` → `delivery/grpc/mapper` (+ tests) → `delivery/grpc`
   (gRPC impl) → `delivery/rest` (`RegisterREST`).
5. **Validation**: add a new file in the shared `internal/validator` package
   for this feature's check methods.
6. **Wire it**: in `container.Build`, construct the repository → usecase →
   handler and register it on the gRPC server and gateway mux, aliasing the
   feature's imports by name (see the `example*` aliases).
7. **Depguard**: add this feature's `internal/features/<name>/delivery`
   package to the `usecase-clean` deny list in `.golangci.yml`.
8. **Verify**: `make lint test build` — depguard will flag any layering
   mistake.
