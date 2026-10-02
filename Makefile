.PHONY: fmt vet lint test test-coverage test-integration build check clean docs-install docs-build docs-check docs-serve

## Format source code
fmt:
	gofmt -s -w .

## Run go vet
vet:
	go vet ./...

## Run golangci-lint
lint:
	golangci-lint run ./...

## Run tests with race detector
test:
	go test -race ./...

## Run tests with coverage
test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

## Run integration tests (requires .env with real credentials)
test-integration:
	go test -race -v -tags=integration ./...

## Build all packages
build:
	go build ./...

## Run all checks (CI equivalent)
check: fmt vet lint test

## Remove build artifacts
clean:
	rm -f coverage.out
	rm -rf site/ docs-site/build/ docs-site/.docusaurus/

## Install private documentation dependencies
docs-install:
	npm --prefix docs-site ci

## Build documentation (fails on broken links)
docs-build:
	npm --prefix docs-site run build

## Typecheck, build, and browser-check documentation
docs-check:
	npm --prefix docs-site run check

## Serve documentation locally
docs-serve:
	npm --prefix docs-site start
