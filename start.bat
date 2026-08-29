@echo off
chcp 65001 >nul
setlocal

REM VulnLab 启动脚本（Windows）
REM
REM 会启动两个 HTTP 服务：
REM   8080  主靶场 —— 你在浏览器里访问的那个
REM   8090  「内部服务」—— SSRF 场景的攻击目标，模拟「只在内网开放的服务」
REM
REM 为什么要起两个：PHP 内置服务器是单进程的，服务端请求自己会死锁
REM （SSRF 场景里靶场要向自己发请求）。分两个端口既解决了这个问题，
REM 也让 SSRF 的因果链更直观 —— 你从 8080 访问，请求实际是发到 8090 的。

set "PORT=8080"
if "%PHP%"=="" set "PHP=php"

"%PHP%" -v >nul 2>nul
if errorlevel 1 (
  echo.
  echo   [错误] 没有找到可用的 PHP。
  echo.
  echo   任选一种方式解决：
  echo     1^) 把 PHP 加入 PATH
  echo     2^) 设置 PHP 环境变量指向 php.exe，例如：
  echo        set PHP=D:\phpStudy\PHPTutorial\php\php-7.2.1-nts\php.exe
  echo     3^) 改用 Docker: docker compose up
  echo.
  echo   需要启用 pdo_sqlite 扩展。
  echo.
  pause
  exit /b 1
)

set /a INTERNAL_PORT=%PORT%+10

echo.
echo   VulnLab 正在启动...
echo.
echo     主靶场      http://127.0.0.1:%PORT%
echo     ├ 首页      http://127.0.0.1:%PORT%/index.php
echo     ├ SQL 注入  http://127.0.0.1:%PORT%/sqli/low.php
echo     ├ XSS       http://127.0.0.1:%PORT%/xss/low.php
echo     ├ 文件上传  http://127.0.0.1:%PORT%/upload/low.php
echo     └ SSRF      http://127.0.0.1:%PORT%/ssrf/low.php
echo.
echo     内部服务    http://127.0.0.1:%INTERNAL_PORT%   （SSRF 场景的目标）
echo.
echo     停止  在这个窗口按 Ctrl+C，并关闭「VulnLab 内部服务」窗口
echo.

start "VulnLab 内部服务" /min "%PHP%" -S 127.0.0.1:%INTERNAL_PORT% -t "%~dp0html"
"%PHP%" -S 127.0.0.1:%PORT% -t "%~dp0html"
