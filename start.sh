#!/usr/bin/env bash
#
# VulnLab 启动脚本（Linux / macOS / Git Bash）
#
# 会启动两个 HTTP 服务：
#   8080  主靶场 —— 你在浏览器里访问的那个
#   8090  「内部服务」—— SSRF 场景的攻击目标，模拟「只在内网开放的服务」
#
# 为什么要起两个：PHP 内置服务器是单进程的，服务端请求自己会死锁
# （SSRF 场景里，靶场要向自己发请求，单进程下无法处理）。
# 分两个端口既解决了这个问题，也让 SSRF 的因果链更直观 ——
# 你从 8080 访问，但请求实际是从服务器发到 8090 的。
#
# 用法：
#   ./start.sh                   使用 PATH 中的 php
#   PHP=/usr/bin/php ./start.sh  指定 php 路径
#   PORT=9090 ./start.sh         换主靶场端口（内部服务自动 +10）

set -euo pipefail

PORT="${PORT:-8080}"
INTERNAL_PORT=$((PORT + 10))
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
DOCROOT="${SCRIPT_DIR}/html"

echo
echo "  VulnLab 正在启动..."
echo
echo "    主靶场      http://127.0.0.1:${PORT}"
echo "    ├ 首页      http://127.0.0.1:${PORT}/index.php"
echo "    ├ SQL 注入  http://127.0.0.1:${PORT}/sqli/low.php"
echo "    ├ XSS       http://127.0.0.1:${PORT}/xss/low.php"
echo "    ├ 文件上传  http://127.0.0.1:${PORT}/upload/low.php"
echo "    └ SSRF      http://127.0.0.1:${PORT}/ssrf/low.php"
echo
echo "    内部服务    http://127.0.0.1:${INTERNAL_PORT}   （SSRF 场景的目标）"
echo
echo "    停止  Ctrl+C"
echo

# 两个服务同时跑，任一退出就一起收尾
"$PHP" -S "127.0.0.1:${INTERNAL_PORT}" -t "$DOCROOT" >/dev/null 2>&1 &
INTERNAL_PID=$!

cleanup() {
  kill "$INTERNAL_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$PHP" -S "127.0.0.1:${PORT}" -t "$DOCROOT"
