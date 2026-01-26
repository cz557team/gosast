#!/bin/bash

# GoSAST 构建脚本
# 支持不同的构建模式

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 默认参数
BUILD_TYPE="release"
WITH_Z3="auto"
OUTPUT="bin/gosast"
TARGET_OS="darwin"
TARGET_ARCH="arm64"

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="debug"
            shift
            ;;
        --with-z3)
            WITH_Z3="yes"
            shift
            ;;
        --without-z3)
            WITH_Z3="no"
            shift
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --os)
            TARGET_OS="$2"
            shift 2
            ;;
        --arch)
            TARGET_ARCH="$2"
            shift 2
            ;;
        --static)
            BUILD_TYPE="static"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "  --debug         Debug build"
            echo "  --with-z3       Force enable Z3"
            echo "  --without-z3    Force disable Z3"
            echo "  --static        Static build (requires Z3 static library)"
            echo "  --output FILE   Output file"
            echo "  --os OS         Target OS (linux, darwin, windows)"
            echo "  --arch ARCH     Target Arch (amd64, arm64)"
            echo ""
            echo "Environment variables:"
            echo "  CGO_CFLAGS      C compiler flags"
            echo "  CGO_LDFLAGS     Linker flags"
            echo "  Z3_ROOT         Z3 installation root"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# 检测 Z3
detect_z3() {
    echo -e "${YELLOW}Detecting Z3...${NC}"

    # 检查环境变量
    if [ -n "$Z3_ROOT" ]; then
        export CGO_CFLAGS="$CGO_CFLAGS -I$Z3_ROOT/include"
        export CGO_LDFLAGS="$CGO_LDFLAGS -L$Z3_ROOT/lib -lz3"
        return 0
    fi

    # 检查 pkg-config
    if command -v pkg-config &> /dev/null; then
        if pkg-config --exists z3; then
            export CGO_CFLAGS="$CGO_CFLAGS $(pkg-config --cflags z3)"
            export CGO_LDFLAGS="$CGO_LDFLAGS $(pkg-config --libs z3)"
            return 0
        fi
    fi

    # 检查常见路径
    local paths=(
        "/opt/homebrew"
        "/usr/local"
        "/opt/local"
        "$HOME/.brew"
        "/opt/anaconda3"
    )

    for path in "${paths[@]}"; do
        if [ -f "$path/lib/libz3.dylib" ] || [ -f "$path/lib/libz3.so" ] || [ -f "$path/lib/libz3.a" ]; then
            export CGO_CFLAGS="$CGO_CFLAGS -I$path/include"
            export CGO_LDFLAGS="$CGO_LDFLAGS -L$path/lib -lz3"
            return 0
        fi
    done

    return 1
}

# 构建
build() {
    local build_tags=""
    local ldflags=""

    # 设置构建类型
    case $BUILD_TYPE in
        debug)
            build_tags="-tags=debug"
            ;;
        static)
            build_tags="-tags=z3,static"
            ldflags="-linkmode external -extldflags \"-static\""
            ;;
        release)
            ldflags="-s -w"  # 去除调试信息
            ;;
    esac

    # 检查是否使用 Z3
    if [ "$WITH_Z3" = "yes" ] || ([ "$WITH_Z3" = "auto" ] && detect_z3); then
        echo -e "${GREEN}Building with Z3 support${NC}"
        build_tags="$build_tags -tags=z3"
    else
        echo -e "${YELLOW}Building without Z3 support${NC}"
        build_tags="$build_tags -tags=!z3"
    fi

    # 设置交叉编译
    if [ -n "$TARGET_OS" ] && [ -n "$TARGET_ARCH" ]; then
        export GOOS=$TARGET_OS
        export GOARCH=$TARGET_ARCH
        echo -e "${YELLOW}Cross-compiling for $TARGET_OS/$TARGET_ARCH${NC}"
    fi

    # 创建输出目录
    mkdir -p "$(dirname "$OUTPUT")"

    # 构建
    echo -e "${GREEN}Building...${NC}"
    echo "CGO_CFLAGS: $CGO_CFLAGS"
    echo "CGO_LDFLAGS: $CGO_LDFLAGS"
    echo "Build tags: $build_tags"
    echo "Output: $OUTPUT"

    go build $build_tags -ldflags "$ldflags" -o "$OUTPUT" ./cmd/scanner

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Build successful!${NC}"

        # 显示二进制信息
        if command -v file &> /dev/null; then
            file "$OUTPUT"
        fi

        if command -v ls &> /dev/null; then
            ls -lh "$OUTPUT"
        fi
    else
        echo -e "${RED}Build failed!${NC}"
        exit 1
    fi
}

# 清理
clean() {
    echo -e "${YELLOW}Cleaning...${NC}"
    rm -rf bin/
    go clean -cache
}

# 主程序
main() {
    case $1 in
        clean)
            clean
            ;;
        *)
            build
            ;;
    esac
}

main "$@"