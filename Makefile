.PHONY: fmt vet lint test test-coverage build check clean

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

## Build all packages
build:
	go build ./...

## Run all checks (CI equivalent)
check: fmt vet lint test

## Remove build artifacts
clean:
	rm -f coverage.out
	rm -rf site/
