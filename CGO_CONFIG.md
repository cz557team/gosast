# CGO 配置说明

## 概述

GoSAST 默认启用 Z3 CGO 支持，提供强大的符号执行能力。构建系统使用构建标签来控制 CGO 行为。

## 构建标签

- **默认行为**（`!noz3`）：启用 Z3 CGO，提供完整的符号执行功能
- **存根模式**（`noz3`）：禁用 Z3 CGO，使用存根实现（不需要 Z3 库）

## 编译方式

### 方法 1：使用 Makefile（推荐）

```bash
# 默认构建（启用 Z3 CGO）
make build

# 显式启用 Z3
make build-z3

# 禁用 Z3（存根模式）
make build-no-z3
```

### 方法 2：直接使用 go build

```bash
# 默认构建（启用 Z3 CGO）
CGO_ENABLED=1 go build -o bin/gosast ./cmd/scanner

# 禁用 Z3（存根模式）
CGO_ENABLED=1 go build -tags=noz3 -o bin/gosast ./cmd/scanner
```

## CGO 配置

### Z3 CGO 实现（`z3_cgo.go`）

```go
//go:build !noz3
// +build !noz3

/*
#cgo CFLAGS: -I/opt/homebrew/anaconda3/include
#cgo darwin LDFLAGS: -L/opt/homebrew/anaconda3/lib -Wl,-rpath,/opt/homebrew/anaconda3/lib -lz3
#cgo linux LDFLAGS: -L/opt/homebrew/anaconda3/lib -lz3
#include <z3.h>
*/
import "C"
```

### 存根实现（`z3_impl_stub.go`）

```go
//go:build noz3
// +build noz3
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `CGO_ENABLED` | 启用/禁用 CGO | `1`（启用） |
| `CGO_CFLAGS` | C 编译器标志 | `-I/opt/homebrew/anaconda3/include` |
| `CGO_LDFLAGS` | 链接器标志 | `-L/opt/homebrew/anaconda3/lib -lz3` |
| `DYLD_LIBRARY_PATH` | 运行时库路径（macOS） | `/opt/homebrew/anaconda3/lib` |
| `LD_LIBRARY_PATH` | 运行时库路径（Linux） | - |
| `GOSAST_DISABLE_Z3` | 运行时禁用 Z3 | - |

## Z3 库要求

### macOS

```bash
# 使用 Homebrew 安装
brew install z3

# 或使用 Anaconda
conda install -c anaconda z3-solver
```

### Linux

```bash
# Ubuntu/Debian
sudo apt-get install z3lib-dev

# CentOS/RHEL
sudo yum install z3-devel
```

## 验证 CGO 状态

### 编译时检查

```bash
$ go build -x -o bin/gosast ./cmd/scanner 2>&1 | grep -i "cgo\|z3"
```

### 运行时检查

启用 CGO 的输出：
```
Found Z3 library at: /opt/homebrew/anaconda3/lib/libz3.dylib
Z3 initialized successfully: 4.15.4.0
Z3 CGO solver initialized successfully
```

存根模式的输出：
```
Found Z3 library at: /opt/homebrew/anaconda3/lib/libz3.dylib
Z3 CGO not available, using stub implementation
```

## 故障排除

### 问题：找不到 Z3 库

**错误信息**：
```
dyld: Library not loaded: @rpath/libz3.dylib
```

**解决方案**：
1. 确认 Z3 已安装：`brew list z3` 或 `conda list z3`
2. 设置 `DYLD_LIBRARY_PATH`：
   ```bash
   export DYLD_LIBRARY_PATH=/opt/homebrew/anaconda3/lib:$DYLD_LIBRARY_PATH
   ```
3. 或重新编译并包含 rpath：
   ```bash
   CGO_ENABLED=1 CGO_LDFLAGS="-L/path/to/z3/lib -Wl,-rpath,/path/to/z3/lib -lz3" go build -o bin/gosast ./cmd/scanner
   ```

### 问题：CGO 未激活

**症状**：看到 "Z3 CGO not available, using stub implementation"

**检查清单**：
1. 确认 `CGO_ENABLED=1`
2. 确认没有使用 `-tags=noz3`
3. 确认 Z3 库在正确路径
4. 重新编译：`go clean -cache && CGO_ENABLED=1 go build`

### 问题：编译错误

**错误信息**：
```
z3.h: No such file or directory
```

**解决方案**：
```bash
export CGO_CFLAGS="-I/path/to/z3/include"
export CGO_LDFLAGS="-L/path/to/z3/lib -lz3"
CGO_ENABLED=1 go build -o bin/gosast ./cmd/scanner
```

## 性能考虑

- **启用 Z3 CGO**：编译时间增加 ~30%，符号执行能力强
- **存根模式**：编译速度快，符号执行能力受限

建议：
- 开发测试：使用默认模式（Z3 CGO）
- CI/CD：根据需求选择
- 生产环境：使用默认模式（Z3 CGO）
