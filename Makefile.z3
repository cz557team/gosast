# Makefile for GoSAST with Z3 support

# 检测 Z3 库
Z3_PATHS = /opt/homebrew/anaconda3/lib/libz3.dylib /opt/homebrew/lib/libz3.dylib /usr/local/lib/libz3.dylib
PKG_CONFIG_PATH = /opt/homebrew/anaconda3/lib/pkgconfig/z3.pc

# 检查 Z3 是否可用
.PHONY: check-z3
check-z3:
	@echo "Checking Z3 availability..."
	@if [ -f "$(firstword $(Z3_PATHS))" ]; then \
		echo "✓ Z3 library found"; \
		echo "Library: $(firstword $(Z3_PATHS))"; \
	else \
		echo "✗ Z3 library not found"; \
		echo "Please install Z3 using:"; \
		echo "  - conda install -c conda-forge z3-solver"; \
		echo "  - brew install z3"; \
	fi
	@if [ -f "$(PKG_CONFIG_PATH)" ]; then \
		echo "✓ Z3 pkg-config found"; \
	else \
		echo "✗ Z3 pkg-config not found"; \
	fi

# 设置环境变量
.PHONY: setup-env
setup-env:
	@echo "Setting up Z3 environment..."
	@if [ -f "/opt/homebrew/anaconda3/lib/libz3.dylib" ]; then \
		export Z3_ROOT=/opt/homebrew/anaconda3; \
		export DYLD_LIBRARY_PATH=$$Z3_ROOT/lib:$$DYLD_LIBRARY_PATH; \
		export CGO_CFLAGS="-I$$Z3_ROOT/include"; \
		export CGO_LDFLAGS="-L$$Z3_ROOT/lib -lz3"; \
		echo "Z3_ROOT=$$Z3_ROOT"; \
		echo "DYLD_LIBRARY_PATH=$$DYLD_LIBRARY_PATH"; \
		echo "CGO_CFLAGS=$$CGO_CFLAGS"; \
		echo "CGO_LDFLAGS=$$CGO_LDFLAGS"; \
	else \
		echo "Z3 not installed in standard location"; \
	fi

# 构建 Z3 标签版本
.PHONY: build-with-z3
build-with-z3:
	@echo "Building with Z3 support..."
	@$(MAKE) setup-env
	CGO_CFLAGS="-I/opt/homebrew/anaconda3/include" \
	CGO_LDFLAGS="-L/opt/homebrew/anaconda3/lib -lz3" \
	go build -tags=z3 -o bin/gosast-z3 ./cmd/scanner
	@echo "✓ Built with Z3 support"

# 构建存根版本
.PHONY: build-stub
build-stub:
	@echo "Building with stub implementation..."
	go build -tags="!z3" -o bin/gosast-stub ./cmd/scanner
	@echo "✓ Built with stub implementation"

# 构建两个版本
.PHONY: build-both
build-both: build-with-z3 build-stub
	@echo "✓ Built both versions"

# 测试 Z3 版本
.PHONY: test-z3
test-z3: build-with-z3
	@echo "Testing Z3 version..."
	DYLD_LIBRARY_PATH=/opt/homebrew/anaconda3/lib:$$DYLD_LIBRARY_PATH ./bin/gosast-z3 test_vulnerable.c

# 测试存根版本
.PHONY: test-stub
test-stub: build-stub
	@echo "Testing stub version..."
	./bin/gosast-stub test_vulnerable.c

# 清理
.PHONY: clean
clean:
	rm -rf bin/
	go clean -cache

# 安装依赖
.PHONY: install-deps
install-deps:
	@echo "Installing dependencies..."
	@if ! command -v conda &> /dev/null; then \
		echo "Installing Z3 via conda..."; \
		conda install -c conda-forge z3-solver -y; \
	elif ! command -v brew &> /dev/null; then \
		echo "Installing Z3 via brew..."; \
		brew install z3; \
	else \
		echo "Please install Z3 manually"; \
	fi

# 显示构建信息
.PHONY: info
info:
	@echo "GoSAST Build Information:"
	@echo "========================"
	@echo "Go version: $(shell go version)"
	@echo "Platform: $(shell uname -s)-$(shell uname -m)"
	@echo "CGO enabled: $(shell go env CGO_ENABLED)"
	@if [ -f "/opt/homebrew/anaconda3/lib/libz3.dylib" ]; then \
		echo "Z3 status: Available at /opt/homebrew/anaconda3/lib/libz3.dylib"; \
	else \
		echo "Z3 status: Not found"; \
	fi
	@echo ""
	@echo "Build targets:"
	@echo "  make check-z3     - Check Z3 availability"
	@echo "  make build-with-z3 - Build with Z3 support"
	@echo "  make build-stub    - Build with stub implementation"
	@echo "  make build-both    - Build both versions"
	@echo "  make test-z3       - Test Z3 version"
	@echo "  make test-stub     - Test stub version"
	@echo "  make install-deps  - Install dependencies"
	@echo "  make clean         - Clean build artifacts"