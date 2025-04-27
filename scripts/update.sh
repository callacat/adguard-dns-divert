#!/bin/bash

# 更新脚本，用于自动下载和更新域名列表
# 运行方式：./scripts/update.sh

# 设置工作目录为脚本所在目录的上一级（即项目根目录）
cd "$(dirname "$0")/.." || exit 1

# 创建必要的目录
mkdir -p config dist

# 检查是否安装了必要的依赖
if ! command -v python3 &> /dev/null; then
    echo "错误：未安装Python 3"
    exit 1
fi

# 检查Python模块
python3 -c "import yaml" &> /dev/null
if [ $? -ne 0 ]; then
    echo "错误：未安装PyYAML模块"
    echo "请运行：pip3 install pyyaml"
    exit 1
fi

# 运行域名提取脚本
echo "开始运行域名提取脚本..."
python3 scripts/extract_domains.py

# 如果dist目录不存在或者为空，说明脚本运行失败
if [ ! -d "dist" ] || [ -z "$(ls -A dist)" ]; then
    echo "错误：域名提取失败"
    exit 1
fi

echo "域名列表更新完成，文件位于dist目录下"
echo "- 国内域名列表：dist/cn_domains.txt"
echo "- 国外域名列表：dist/foreign_domains.txt"
echo "- 国内DNS服务器：dist/cn_dns_active.txt"
echo "- 国外DNS服务器：dist/foreign_dns_active.txt"
