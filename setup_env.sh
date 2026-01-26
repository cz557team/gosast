#!/bin/bash
# 设置 Z3 开发环境变量

# Z3 安装路径（Conda 安装）
export Z3_HOME=/opt/homebrew/anaconda3
export LD_LIBRARY_PATH=$Z3_HOME/lib:$LD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=$Z3_HOME/lib:$DYLD_LIBRARY_PATH
export PKG_CONFIG_PATH=$Z3_HOME/lib/pkgconfig:$PKG_CONFIG_PATH

# CGO 编译时需要的环境变量
export CGO_CFLAGS="-I$Z3_HOME/include"
export CGO_LDFLAGS="-L$Z3_HOME/lib -lz3"

echo "Z3 开发环境已设置："
echo "  Z3_HOME: $Z3_HOME"
echo "  库文件: $Z3_HOME/lib"
echo "  头文件: $Z3_HOME/include"