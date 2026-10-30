<?php
/**
 * 诱饵页的公共外壳。
 *
 * 这些页面只有一个用途：给扫描器提供「看起来能注入、实际输出已编码」的目标。
 * 全部输出都走 esc()，参数不进入任何拼接语句。
 */
declare(strict_types=1);

function esc(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function shell_start(string $title): void
{
    ?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= esc($title) ?> · VulnLab 诱饵页</title>
<style>
  body{margin:0;background:#f8fafc;color:#0f172a;font:15px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
  .wrap{max-width:820px;margin:0 auto;padding:32px 20px 48px}
  .tag{display:inline-block;padding:2px 8px;border-radius:999px;background:#dcfce7;color:#166534;font-size:12px}
  h1{font-size:24px;margin:14px 0 6px}
  .sub{color:#475569;margin:0 0 22px}
  .card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:18px;margin:14px 0}
  pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;font-size:13px}
  code{font-family:ui-monospace,Consolas,monospace}
  input,textarea{width:100%;padding:8px 10px;border:1px solid #cbd5e1;border-radius:6px;font-family:inherit;box-sizing:border-box}
  button{margin-top:10px;padding:8px 16px;border:0;border-radius:6px;background:#0f172a;color:#fff;cursor:pointer}
  .muted{color:#64748b;font-size:13px}
  a{color:#1d4ed8}
</style>
</head>
<body><div class="wrap">
<span class="tag">诱饵页 · 安全实现</span>
<h1><?= esc($title) ?></h1>
<?php
}

function shell_end(): void
{
    ?></div></body></html><?php
}
