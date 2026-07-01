# Load local env vars (gitignored; see .env.example) so ARAQUANID_* vars set
# there reach both `go run` and the migrate DSN below — the single source
# of truth is the environment, not a yaml file.
-include .env
export

MODULE        := github.com/kurnhyalcantara/araquanid
BINARY        := araquanid
IMAGE_TAG     ?= latest
COMPOSE_FILE  := deployments/docker-compose.yml
COMPOSE       := docker compose --project-directory . -f $(COMPOSE_FILE)
MIGRATIONS    := migrations

# Derived from the same ARAQUANID_POSTGRES__* vars the app reads, so migrations
# and the server never drift apart. Override with `make migrate-up POSTGRES_DSN=...`
# or set ARAQUANID_MIGRATE_DATABASE_URL (.env) when the password has reserved URL chars.
POSTGRES_DSN ?= $(if $(ARAQUANID_MIGRATE_DATABASE_URL),$(ARAQUANID_MIGRATE_DATABASE_URL),postgres://$(if $(ARAQUANID_POSTGRES__USER),$(ARAQUANID_POSTGRES__USER),araquanid):$(if $(ARAQUANID_POSTGRES__PASSWORD),$(ARAQUANID_POSTGRES__PASSWORD),araquanid)@$(if $(ARAQUANID_POSTGRES__HOST),$(ARAQUANID_POSTGRES__HOST),localhost):$(if $(ARAQUANID_POSTGRES__PORT),$(ARAQUANID_POSTGRES__PORT),5432)/$(if $(ARAQUANID_POSTGRES__DATABASE),$(ARAQUANID_POSTGRES__DATABASE),araquanid)?sslmode=$(if $(ARAQUANID_POSTGRES__SSL_MODE),$(ARAQUANID_POSTGRES__SSL_MODE),disable))

VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT        ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE          ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS       := -s -w \
  -X main.buildVersion=$(VERSION) \
  -X main.buildCommit=$(COMMIT) \
  -X main.buildDate=$(DATE)

.PHONY: build run test test-integration lint vet proto-update \
        migrate-up migrate-down migrate-create docker-build compose-up compose-down compose-migrate tidy tools

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/server

run:
	go run ./cmd/server serve

test:
	go test -race -cover ./...

test-integration:
	go test -race -tags=integration ./test/integration/...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# Protos live in the centralized contract repo (github.com/kurnhyalcantara/probopass).
# This pulls the latest generated stubs; edit the contracts in that repo, not here.
proto-update:
	go get github.com/kurnhyalcantara/probopass@latest
	go mod tidy

migrate-up:
	migrate -path $(MIGRATIONS) -database "$(POSTGRES_DSN)" up

migrate-down:
	migrate -path $(MIGRATIONS) -database "$(POSTGRES_DSN)" down 1

# Usage: make migrate-create NAME=create_foo
migrate-create:
	migrate create -ext sql -dir $(MIGRATIONS) -seq $(NAME)

docker-build:
	docker build -f deployments/Dockerfile \
	  --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) \
	  -t $(BINARY):$(IMAGE_TAG) .

compose-up:
	$(COMPOSE) --profile app up -d

compose-down:
	$(COMPOSE) --profile app down

compose-migrate:
	$(COMPOSE) --profile tools run --rm migrate

tidy:
	go mod tidy

tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
