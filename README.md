# GoSAST

Go 静态应用安全测试工具 (Static Application Security Testing)

## 环境要求

- Go 1.25.4+
- Z3 SMT Solver

## 快速开始

### 1. 安装 Z3 环境

首先需要安装 Z3。在 macOS 上可以通过 Conda 安装：

```bash
# 使用 Conda 安装 Z3
conda install -c conda-forge z3
```

或通过 Homebrew 安装：

```bash
brew install z3
```

### 2. 配置环境

运行环境配置脚本：

```bash
./setup_env.sh
```

该脚本会设置以下环境变量：
- `Z3_HOME`: Z3 安装路径
- `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH`: 库文件搜索路径
- `PKG_CONFIG_PATH`: pkg-config 搜索路径
- `CGO_CFLAGS`: C 编译器头文件路径
- `CGO_LDFLAGS`: 链接器库文件路径

### 3. 编译项目

运行构建脚本：

```bash
./build.sh
```

编译成功后，二进制文件将输出到 `bin/gosast`。


## 环境变量

如果使用非标准路径安装 Z3，可以通过以下环境变量指定：

- `Z3_ROOT`: Z3 安装根目录
- `CGO_CFLAGS`: C 编译器标志
- `CGO_LDFLAGS`: 链接器标志

## 文档

- [CGO 配置说明](CGO_CONFIG.md)
- [设计文档](design.md)
