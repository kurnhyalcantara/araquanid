# araquanid

Production-grade Go microservice template — the standard blueprint for new
services. Feature-based Clean Architecture (organized by feature, with
`domain`/`validator` as shared cross-cutting packages), gRPC-first with
grpc-gateway REST, PostgreSQL, Redis, OpenTelemetry + Prometheus, Docker, and
GitHub Actions CI.

The repository ships with one complete reference slice — `example`
(a CRUD resource: create/get/list/update/delete with token-based list
pagination) — exercising every layer of the architecture. Read
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the rules; mirror the
`example` slice's shape for new capabilities.

## Requirements

- Go 1.25+
- Postgres + Redis reachable for local dev — either the shared `koer-network`
  Postgres/Redis from the infernape platform (what `deployments/docker-compose.yml`
  joins), or your own local instances; `deployments/docker-compose.yml` itself
  only adds araquanid as an upstream, it doesn't start Postgres/Redis
- Proto contracts live in [`github.com/kurnhyalcantara/probopass`](https://github.com/kurnhyalcantara/probopass);
  this service imports the generated Go stubs as a module dependency. `make
  proto-update` pulls the latest.
- `make tools` installs golangci-lint and migrate

## Quickstart

```sh
cp .env.example .env         # fill in real values; see Configuration below
scripts/migrate.sh up        # or: make migrate-up (needs the migrate CLI)
make run
```

Smoke test over REST (gateway on :8080):

```sh
# create → returns the example resource
curl -s -X POST localhost:8080/v1/examples -d '{"name":"foo","description":"bar"}'

# read one
curl -s localhost:8080/v1/examples/<id>

# list (paginated)
curl -s 'localhost:8080/v1/examples?page.page_size=20'

# update
curl -s -X PATCH localhost:8080/v1/examples/<id> -d '{"name":"foo2","description":"baz"}'

# delete
curl -s -X DELETE localhost:8080/v1/examples/<id>
```

gRPC is on :9090 (reflection enabled — `grpcurl -plaintext localhost:9090 list`).
Ops endpoints on :9100: `/metrics`, `/healthz`, `/readyz`.

## Commands

| Command | Purpose |
|---|---|
| `make run` / `make build` | run / build `cmd/server` |
| `make test` | unit tests (race + coverage) |
| `make test-integration` | integration tests (needs compose services + migrations) |
| `make lint` | golangci-lint, including depguard architecture rules |
| `make proto-update` | pull the latest generated stubs from the probopass contract repo |
| `make migrate-up` / `make migrate-down` | apply / roll back one migration |
| `make migrate-create NAME=...` | create a new migration pair |
| `make docker-build` | build the production image |
| `make compose-up` / `make compose-down` | start / stop araquanid against the shared `koer-network` |
| `make compose-migrate` | run migrations via the dockerized `migrate` service |

## Project structure

```
cmd/server/       cobra CLI: serve (config → container → run) + version
config/           config loader (defaults < ARAQUANID_* env; optional --config yaml overlay)
internal/
  domain/         shared, pure domain models and invariants (one file per feature)
  features/
    example/      one vertical slice per capability
      delivery/
        grpc/     gRPC server impl (+ dto, mapper)
        rest/     REST gateway registration
      repository/ outbound port (interface) + adapters (db/, redis/, kafka/ as needed)
      usecase/    application logic (interface + impl; tests against a fake repo)
  validator/      shared input validation → apperror.CodeInvalidArgument (one file per feature)
container/        composition root (Build wires everything; Close tears it down)
migrations/       golang-migrate SQL files
deployments/      Dockerfile + docker-compose
test/integration/ integration tests (`-tags=integration`)
docs/             architecture guidelines
```

Proto contracts and their generated Go stubs live in the centralized
[`probopass`](https://github.com/kurnhyalcantara/probopass) repository and are
consumed as a module dependency.

## Configuration

Environment variables are the single source of truth: precedence is defaults
(`config/config.go`) < environment. Convention: `ARAQUANID_` prefix, `__` for
nesting — `ARAQUANID_POSTGRES__HOST=db` overrides `postgres.host`. Copy
`.env.example` to `.env` (gitignored, auto-loaded by `make`) for local dev.
`Makefile`'s `migrate-up`/`migrate-down` read the same `ARAQUANID_POSTGRES__*`
vars so migrations never drift from the app. A yaml file can still be layered
in via `--config path.yaml` for local stacking, but it's optional and loaded
before env, so env always wins.

## Using this template for a new service

1. Copy the repo; replace module path `github.com/kurnhyalcantara/araquanid` and
   the `ARAQUANID_` env prefix (`config/config.go`).
2. Replace the `example` slice with your first real capability following
   [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#adding-or-changing-a-capability-recipe).
3. Update `app.name` in config and the compose/CI image names.
