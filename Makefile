.PHONY: help check test lint fmt vuln gen up down dev seed build deploy-test
# part:keel
.PHONY: test-pg test-mysql
# /part:keel

export CGO_ENABLED = 0
# part:keel
export COMPOSE_PROFILES ?= pg,mail
# /part:keel
# part:postgres
profiles += pg
# /part:postgres
# part:mysql
profiles += mysql
# /part:mysql
# part:mail
profiles += mail
# /part:mail
comma := ,
export COMPOSE_PROFILES ?= $(subst $() ,$(comma),$(strip $(profiles)))

BUILDINFO := github.com/PuckxPuck/keel/internal/kit/buildinfo
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --verify -q HEAD)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

check: ## Format, lint, vet, govulncheck and tests
	go run ./cmd/keel check

test: ## Tests with -race on every reachable database (ARGS="--pkg ./internal/kit/money --run TestAllocate")
	go run ./cmd/keel test $(ARGS)

# part:keel
test-pg: ## Tests on Postgres only
	go run ./cmd/keel test --engine postgres $(ARGS)

test-mysql: ## Tests on MySQL only
	go run ./cmd/keel test --engine mysql $(ARGS)
# /part:keel

lint: ## golangci-lint
	go run ./cmd/keel lint

fmt: ## Format code
	go run ./cmd/keel fmt

vuln: ## govulncheck
	go run ./cmd/keel vuln

gen: ## Regenerate the Jet types in internal/dbgen and the OpenAPI documents in spec
	go run ./cmd/keel gen

up: ## Start local services (COMPOSE_PROFILES, default pg,mail)
	docker compose up -d

down: ## Stop local services
	docker compose down

dev: ## Run the API with .env loaded (APP_ENV defaults to local, dev login on)
	@set -a; if [ -f .env ]; then . ./.env; fi; set +a; APP_ENV=$${APP_ENV:-local} APP_DEV_LOGIN=$${APP_DEV_LOGIN:-true} go run ./cmd/app serve

seed: ## Local only: migrate, then setup and seed (with .env loaded)
	@set -a; if [ -f .env ]; then . ./.env; fi; set +a; APP_ENV=$${APP_ENV:-local} go run ./cmd/app migrate && APP_ENV=$${APP_ENV:-local} go run ./cmd/app db:seed

build: ## Release binary bin/app and its bin/app.sha256 (VERSION, COMMIT, BUILD_TIME stamped)
	@test -n "$(BUILD_TIME)" || { echo "BUILD_TIME is required: the build time in RFC 3339 UTC" >&2; exit 1; }
	mkdir -p bin
	go build -trimpath -ldflags "-s -w -X $(BUILDINFO).version=$(VERSION) -X $(BUILDINFO).commit=$(COMMIT) -X $(BUILDINFO).buildTime=$(BUILD_TIME)" -o bin/app ./cmd/app
	cd bin && (sha256sum app 2>/dev/null || shasum -a 256 app) > app.sha256

deploy-test: ## release.sh switches and failures under load behind nginx (Docker, local Postgres; DEPLOYTEST_DOCKER=1 adds --docker mode)
	go test -tags deploytest -count=1 -timeout 3m -v ./deploy/test
