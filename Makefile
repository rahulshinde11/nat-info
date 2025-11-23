.PHONY: build build-all clean docker-build linux darwin help

BINARY_NAME := nat-info
VERSION := $(shell date +%Y%m%d-%H%M%S)
BUILD_DIR := dist
LDFLAGS := -s -w -X main.version=$(VERSION)

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build directory"

build-all: linux darwin ## Build for all platforms

linux: ## Build Linux binaries (amd64 and arm64)
	@echo "Building Linux binaries..."
	@mkdir -p $(BUILD_DIR)
	@$(MAKE) docker-build OS=linux ARCH=amd64
	@$(MAKE) docker-build OS=linux ARCH=arm64

darwin: ## Build macOS binaries (amd64 and arm64)
	@echo "Building macOS binaries..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)-darwin-*

docker-build: ## Build Linux binary using Docker (internal target)
	@docker run --rm \
		-v "$(PWD)":/usr/src/nat-info \
		-w /usr/src/nat-info \
		-e GOOS=$(OS) \
		-e GOARCH=$(ARCH) \
		-e CGO_ENABLED=0 \
		golang:1.22-alpine \
		sh -c "go build -ldflags '$(LDFLAGS)' -trimpath -o $(BUILD_DIR)/$(BINARY_NAME)-$(OS)-$(ARCH) ."
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)-$(OS)-$(ARCH)

build: build-all ## Alias for build-all




