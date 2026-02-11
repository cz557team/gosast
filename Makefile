# GoSAST Makefile

# Z3 环境变量
export CGO_CFLAGS = -I/opt/homebrew/anaconda3/include
export CGO_LDFLAGS = -L/opt/homebrew/anaconda3/lib -lz3
export DYLD_LIBRARY_PATH = /opt/homebrew/anaconda3/lib

# 默认目标：启用 CGO 和 Z3 编译
.PHONY: all
all: build

# 编译项目（默认启用 Z3 CGO）
# CGO 通过构建标签 !noz3 自动启用
.PHONY: build
build:
	@echo "Building with Z3 CGO support (default)..."
	CGO_ENABLED=1 go build -o bin/gosast ./cmd/scanner
	@echo "Build complete: bin/gosast (Z3 CGO enabled)"

# 编译项目（显式启用 Z3）
.PHONY: build-z3
build-z3:
	@echo "Building with Z3 CGO support..."
	CGO_ENABLED=1 go build -o bin/gosast ./cmd/scanner
	@echo "Build complete: bin/gosast (Z3 CGO enabled)"

# 编译项目（禁用 Z3，使用存根）
.PHONY: build-no-z3
build-no-z3:
	@echo "Building without Z3 (stub mode)..."
	CGO_ENABLED=1 go build -tags=noz3 -o bin/gosast-stub ./cmd/scanner
	@echo "Build complete: bin/gosast-stub (Z3 disabled, stub mode)"

# 运行测试
.PHONY: test
test: build
	DYLD_LIBRARY_PATH=/opt/homebrew/anaconda3/lib ./bin/gosast test_int_overflow.c

# 运行 UAF 测试
.PHONY: test-uaf
test-uaf: build
	DYLD_LIBRARY_PATH=/opt/homebrew/anaconda3/lib ./bin/gosast -v test_vulnerable.c

# 安装到 $GOPATH/bin 或 $GOBIN
.PHONY: install
install: build
	@echo "Installing gosast..."
	@install -d $(shell go env GOPATH)/bin 2>/dev/null || true
	@install -d $(shell go env GOBIN) 2>/dev/null || true
	@if [ -n "$(shell go env GOBIN)" ]; then \
		install bin/gosast $(shell go env GOBIN)/gosast; \
		echo "Installed to $(shell go env GOBIN)/gosast"; \
	else \
		install bin/gosast $(shell go env GOPATH)/bin/gosast; \
		echo "Installed to $(shell go env GOPATH)/bin/gosast"; \
	fi

# 清理
.PHONY: clean
clean:
	rm -rf bin/

# 安装依赖
.PHONY: deps
deps:
	go mod tidy

# 格式化代码
.PHONY: fmt
fmt:
	go fmt ./...

# 帮助
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build       - Build with Z3 CGO support (default)"
	@echo "  build-z3    - Build with Z3 CGO support (same as build)"
	@echo "  build-no-z3 - Build without Z3 (stub mode)"
	@echo "  install     - Build and install gosast to $$GOPATH/bin or $$GOBIN"
	@echo "  test        - Run integer overflow test"
	@echo "  test-uaf    - Run UAF test"
	@echo "  clean       - Remove build artifacts"
	@echo "  deps        - Install dependencies"
	@echo "  fmt         - Format code"
	@echo ""
	@echo "CGO Configuration:"
	@echo "  Z3 CGO is enabled by default via build tag '!noz3'"
	@echo "  To disable Z3, use 'go build -tags=noz3' or 'make build-no-z3'"
	@echo ""
	@echo "Environment Variables:"
	@echo "  CGO_ENABLED=1           - Enable CGO (required for Z3)"
	@echo "  GOSAST_DISABLE_Z3=1     - Runtime Z3 disable"
	@echo "  DYLD_LIBRARY_PATH       - Path to Z3 library at runtime"
