.PHONY: run build test test-integration lint fmt vet migrate-up migrate-down docker-up docker-down

run:
	go run ./cmd/server

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/server ./cmd/server

test:
	go test ./... -race -covermode=atomic -coverprofile=coverage.out

test-integration:
	go test ./test/integration/... -tags=integration -race

lint:
	golangci-lint run ./...

fmt:
	gofmt -l -w .

vet:
	go vet ./...

# Requires golang-migrate: https://github.com/golang-migrate/migrate
migrate-up:
	migrate -path migrations -database "$$DATABASE_URL" up

migrate-down:
	migrate -path migrations -database "$$DATABASE_URL" down 1

docker-up:
	docker compose -f docker/docker-compose.yml up --build

docker-down:
	docker compose -f docker/docker-compose.yml down -v
