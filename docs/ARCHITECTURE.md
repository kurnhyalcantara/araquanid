# Architecture

This service follows a **layered Clean Architecture** with DDD-inspired domain
modeling. The codebase is organized **by responsibility, not by feature**: each
layer is a single top-level package under `internal/`. It is **gRPC-first**: the
proto contract is the source of truth — it lives in the centralized
[`probopass`](https://github.com/kurnhyalcantara/probopass) contract repo and
this service consumes the generated Go stubs as a module dependency — and REST is
derived from it via grpc-gateway. This document is the blueprint for every
service built from this template. The `example` CRUD slice is the reference
implementation every new capability should mirror.

## Layers

```
            ┌────────────────────────────────────────────┐
 inbound →  │ handler (grpc / rest)  ← transport types   │
            ├────────────────────────────────────────────┤
            │ usecase  ← application logic, ports        │
            ├────────────────────────────────────────────┤
            │ domain   ← entities, invariants (pure)     │
            ├────────────────────────────────────────────┤
 outbound → │ repository ← adapters: pg, redis, APIs ... │
            └────────────────────────────────────────────┘
              platform = infra init   container = wiring
```

| Layer | Location | Responsibility |
|---|---|---|
| Domain | `internal/domain` | Entities, value objects, invariants, domain errors |
| Usecase | `internal/usecase` | Application logic; depends only on domain + repository ports |
| Repository | `internal/repository` | Outbound port (interface) + adapters (`postgres.go`, `redis_cache.go`, …) |
| Handler | `internal/handler` (+ `dto`, `mapper`) | Inbound adapter: gRPC server impl + REST gateway registration; its dtos and mappers |
| Validator | `internal/validator` | Converts validation failures into `apperror.CodeInvalidArgument` |
| Platform | `pkg/platform/*` (in `kingler`) | Infrastructure **initialization only** (clients, servers) |
| Container | `container/` | Composition root: `Build` wires the whole graph, `Close` tears it down |
| Shared | `kingler/pkg/*` | Cross-cutting concerns (`apperror`, `ctxutil`, `middleware`, `pagination`, …) |

## Dependency rules

Enforced by `depguard` in `.golangci.yml` — violations fail `make lint` and CI.

1. **Domain is pure.** `internal/domain/**` imports stdlib and other domain
   packages only. Never transport (the probopass proto stubs, grpc),
   infrastructure (`platform/`, drivers), or the handler.
2. **Usecases see ports, not adapters.** A usecase imports its domain, the
   `repository` *interface*, and shared `kingler/pkg/*` helpers. It must not
   import the probopass proto stubs, `platform/`, drivers, or `internal/handler`
   (including `handler/dto` and `handler/mapper`). When a usecase needs a
   platform capability, it defines a small interface where it is consumed and the
   container injects the platform implementation.
3. **Transport types stop at the mapper.** Only `internal/handler` and
   `internal/handler/mapper` may import the probopass proto stubs. Proto messages
   never reach usecases or the domain.
4. **Platform contains no business logic.** `platform/**` may import third-party
   libraries, never `internal/` or `container/`.
5. **The container imports everything; nothing imports the container** (except `cmd/`).

## Repository definition

A repository is an **outbound adapter abstraction** — the port through which a
usecase reaches anything outside the process:

- PostgreSQL, Redis
- other gRPC/HTTP services
- third-party APIs
- message brokers

It is *not* limited to database access. The interface lives in
`internal/repository`, named for the capability it provides, and is consumed by
the usecase. Implementations live next to it (`postgres.go`, `redis_cache.go`,
…) and can be composed — see `NewRedisCache`, a read-through cache decorator that
wraps the Postgres repository while the usecase still sees a single
`Repository`.

## Package structure

```
internal/
├── domain/            # entities, invariants, domain errors (pure)
├── usecase/           # interface + implementation; application logic (+ tests against a fake repo)
├── repository/        # outbound port (interface) + adapters (postgres.go, redis_cache.go)
├── validator/         # converts validation failures into apperror.CodeInvalidArgument
└── handler/
    ├── handler.go     # implements the generated *ServiceServer; thin: validate → map → usecase → map
    ├── rest.go        # registers the grpc-gateway translation onto the shared mux
    ├── dto/           # handler input structs (with `validate` tags)
    └── mapper/        # pure functions: proto ⇄ dto ⇄ domain/usecase types
```

Usecase methods take primitive/domain inputs and return domain or usecase-owned
types (e.g. `usecase.ExampleList`); the `dto` package is a handler concern, so
the usecase never depends on it.

## Dependency injection strategy

Manual constructor wiring — no DI framework, no codegen, no reflection.

- `container`: `Build(ctx, cfg)` is the single composition root. It calls the
  platform and usecase/handler constructors directly — config → platform →
  repositories → usecases → handlers → middleware → servers, in that order —
  making composition decisions inline (e.g. wrapping the Postgres repository in
  the Redis cache) with a comment, and registers the handler on the gRPC server
  and gateway mux. `Close(ctx)` releases resources in reverse. There is no
  separate provider or registry layer. `cmd/server` is a cobra CLI; its `serve`
  command loads config, calls `container.Build`, and runs the servers.
- Platform constructors take a single `Config` struct (the source of truth), not
  functional options — e.g. `postgres.New(ctx, postgres.Config{DSN: …})`.

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
- Layer files: `handler.go`, `usecase.go`, `repository.go` (interface),
  `postgres.go`, `redis_cache.go`, `dto.go`, `mapper.go`, `validator.go`.
- Interfaces are named for the role (`Repository`, `Usecase`); implementations
  are unexported (`postgresRepository`) and returned from constructors
  (`NewPostgres`).
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
2. **Domain**: add the entity, invariants, and errors in `internal/domain`.
3. **Migration**: `make migrate-create NAME=create_{name}s`.
4. **Layers**: extend each layer following the `example` slice — `repository`
   (interface + adapters) → `usecase` (+ tests against a fake repository) →
   `handler/dto` → `handler/mapper` (+ tests) → `validator` → `handler`
   (gRPC impl + `RegisterREST`).
5. **Wire it**: in `container.Build`, construct the repository → usecase →
   handler and register it on the gRPC server and gateway mux.
6. **Verify**: `make lint test build` — depguard will flag any layering
   mistake.
