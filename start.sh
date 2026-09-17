#!/usr/bin/env bash
#
# VulnLab 启动脚本（Linux / macOS / Git Bash）
#
# 用法：
#   ./start.sh                   使用 PATH 中的 php
#   PHP=/usr/bin/php ./start.sh  指定 php 路径
#   PORT=9090 ./start.sh         换端口

set -euo pipefail

PORT="${PORT:-8080}"
PHP="${PHP:-php}"

if ! command -v "$PHP" >/dev/null 2>&1; then
  cat <<'EOF'

  [错误] 没有找到可用的 PHP。

  任选一种方式解决：
    1) 安装 PHP 7.2+ 并确保在 PATH 中
    2) 用环境变量指定： PHP=/path/to/php ./start.sh
    3) 改用 Docker：   docker compose up

  需要启用 pdo_sqlite 扩展。

EOF
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo
echo "  VulnLab 正在启动..."
echo
echo "    地址  http://127.0.0.1:${PORT}"
echo "    首页  http://127.0.0.1:${PORT}/index.php"
echo "    注入  http://127.0.0.1:${PORT}/sqli/low.php"
echo
echo "    停止  Ctrl+C"
echo

exec "$PHP" -S "127.0.0.1:${PORT}" -t "${SCRIPT_DIR}/html"
