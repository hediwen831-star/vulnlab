@echo off
rem ============================================================
rem  VulnLab 启动脚本（Windows）
rem
rem  用法：
rem    start.bat                             使用 PATH 中的 php
rem    set PHP=D:\php\php.exe && start.bat   指定 php.exe
rem ============================================================

chcp 65001 >nul
setlocal

set "PORT=8080"
if "%PHP%"=="" set "PHP=php"

"%PHP%" -v >nul 2>nul
if errorlevel 1 (
  echo.
  echo   [错误] 没有找到可用的 PHP。
  echo.
  echo   任选一种方式解决：
  echo     1^) 把 PHP 加入系统 PATH
  echo     2^) 用环境变量指定 php.exe 路径，例如：
  echo          set PHP=D:\phpStudy\PHPTutorial\php\php-7.2.1-nts\php.exe
  echo          start.bat
  echo     3^) 改用 Docker：docker compose up
  echo.
  echo   需要 PHP 7.2 或更高版本，且启用 pdo_sqlite 扩展。
  echo.
  pause
  exit /b 1
)

echo.
echo   VulnLab 正在启动...
echo.
echo     地址  http://127.0.0.1:%PORT%
echo     首页  http://127.0.0.1:%PORT%/index.php
echo     注入  http://127.0.0.1:%PORT%/sqli/low.php
echo.
echo     停止  Ctrl+C
echo.

"%PHP%" -S 127.0.0.1:%PORT% -t "%~dp0html"
