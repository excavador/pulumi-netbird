# Justfile for Pulumi NetBird Provider
# 
# All commands run inside devbox environment, so "go" and "pulumi" can be used directly.
# Execute via: devbox run -- just <command>

# Provider version (update this when releasing)
PROVIDER_VERSION := "0.2.4"

# Build provider binary
# Usage: just build-provider
build-provider:
    @echo "🔨 Building provider binary..."
    export CGO_ENABLED=0
    mkdir -p bin
    go build -o bin/pulumi-resource-netbird ./provider/cmd/pulumi-resource-netbird
    @echo "✅ Provider binary built: bin/pulumi-resource-netbird"

# Install provider plugin
# Usage: just install-provider
install-provider: build-provider
    @echo "📦 Installing Pulumi NetBird provider plugin..."
    pulumi plugin install resource netbird {{PROVIDER_VERSION}} \
      -f ./bin/pulumi-resource-netbird
    @echo "✅ Provider plugin installed"

# Generate Go SDK
# Usage: just gen-sdk-go
gen-sdk-go: build-provider
    @echo "🔨 Generating Go SDK from provider..."
    export CGO_ENABLED=0
    pulumi package gen-sdk \
      ./bin/pulumi-resource-netbird \
      --language go
    @echo "✅ Go SDK generated in sdk"

# Generate Python SDK
# Usage: just gen-sdk-python
gen-sdk-python: build-provider
    @echo "🔨 Generating Python SDK from provider..."
    export CGO_ENABLED=0
    pulumi package gen-sdk \
      ./bin/pulumi-resource-netbird \
      --language python \
      --out sdk/python
    @echo "✅ Python SDK generated in sdk/python"

# Generate TypeScript/Node.js SDK
# Usage: just gen-sdk-nodejs
gen-sdk-nodejs: build-provider
    @echo "🔨 Generating TypeScript/Node.js SDK from provider..."
    export CGO_ENABLED=0
    pulumi package gen-sdk \
      ./bin/pulumi-resource-netbird \
      --language nodejs \
      --out sdk/nodejs
    @echo "✅ TypeScript SDK generated in sdk/nodejs"

# Generate all SDKs
# Usage: just gen-sdk-all
gen-sdk-all: build-provider
    @echo "🔨 Generating all SDKs from provider..."
    just gen-sdk-go
    just gen-sdk-python
    just gen-sdk-nodejs
    @echo "✅ All SDKs generated"

# Setup provider (build, install, and generate Go SDK)
# Usage: just setup-provider
setup-provider: build-provider install-provider gen-sdk-go
    @echo "✅ Provider setup complete"

# Format code using gofmt
# Usage: just fmt
fmt:
    gofmt -w .

# Manage dependencies
# Usage: just deps
deps:
    go mod tidy
    go mod verify

# Build all packages
# Usage: just build
build:
    go build ./...

# Run tests
# Usage: just test
test:
    go test ./...

# Run tests with verbose output
# Usage: just test-verbose
test-verbose:
    go test -v ./...

# Run tests with coverage
# Usage: just test-coverage
test-coverage:
    go test -cover ./...

# Run linter
# Usage: just lint
lint:
    golangci-lint run ./...

# Run all checks (build, test, lint)
# Usage: just check
check: build test lint
    @echo "✅ All checks passed"

# Cross-build provider binaries for multiple platforms
# Usage: just cross-build
cross-build:
    @echo "🔨 Cross-building provider binaries..."
    export CGO_ENABLED=0
    mkdir -p dist
    @for platform in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
        GOOS=$${platform%/*}; \
        GOARCH=$${platform#*/}; \
        BINARY_NAME="pulumi-resource-netbird"; \
        if [ "$$GOOS" = "windows" ]; then \
            BINARY_NAME="$$BINARY_NAME.exe"; \
        fi; \
        GOOS=$$GOOS GOARCH=$$GOARCH go build -o "dist/$$BINARY_NAME" ./provider/cmd/pulumi-resource-netbird; \
        ARCHIVE_NAME="pulumi-resource-netbird-v{{PROVIDER_VERSION}}-$$GOOS-$$GOARCH.tar.gz"; \
        tar -czf "dist/$$ARCHIVE_NAME" -C dist "$$BINARY_NAME"; \
        rm "dist/$$BINARY_NAME"; \
    done
    @cd dist && sha256sum *.tar.gz > checksums.txt || true
    @echo "✅ Cross-build complete"
