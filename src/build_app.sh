#!/bin/bash

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig
curDir=$(cd $(dirname $0);pwd) 
cd $curDir

echo "Current directory: $curDir"

echo ""
echo -e "\033[36m [INFO] meson build \033[m"
meson build

echo ""
echo -e "\033[36m [INFO] ninja -C build \033[m"
ninja -C build

