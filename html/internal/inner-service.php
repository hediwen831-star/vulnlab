<?php
/**
 * 模拟的「内网服务」—— SSRF 场景的攻击目标。
 *
 * 这个文件模拟真实世界里的一类服务：
 * **只应该被内网访问，没有做认证**（因为"反正外面访问不到"）。
 *
 * 这类服务非常常见：内部管理接口、监控指标端点、只监听在 127.0.0.1 的调试接口。
 * 它们的安全性完全建立在「外部访问不到」这个前提上 ——
 * 而 SSRF 恰好打破的就是这个前提。
 *
 * ⚠️ 注意：本靶场跑在单机上，浏览器其实也能直接打开这个页面，
 * 所以「内网隔离」在物理上并没有真正实现。
 * 但从**教学角度**它完整演示了 SSRF 的因果链：
 *   外部请求 → 服务端代为发起请求 → 触达了本不该被触达的服务
 *
 * 真实环境里，被 SSRF 打到的目标通常是：
 *   · 云元数据接口（169.254.169.254）—— 可直接拿到云主机临时凭据
 *   · 内网未授权的管理后台
 *   · Redis / MySQL / Elasticsearch 等无认证的数据服务
 *   · 只监听回环地址的调试端点
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

$response = [
    'service'   => 'internal-admin-api',
    'version'   => '2024.1',
    'secret'    => 'VULNLAB{ssrf_reached_internal_service}',
    'flag_note' => '这个接口不应被外部直接访问，但服务端代为请求就能读到它',
    'internal_resources' => [
        'db_dsn'    => 'mysql://app:Str0ngP@ss@10.0.0.12:3306/production',
        'redis'     => 'redis://10.0.0.13:6379/0',
        'api_token' => 'sk-internal-9f3a2b7c1d8e4f5a',
    ],
    'debug' => [
        'note'      => '调试信息本不该出现在生产接口里',
        'php_version' => PHP_VERSION,
        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
    ],
];

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
