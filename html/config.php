<?php
/**
 * VulnLab 全局配置与数据库初始化。
 *
 * 设计取舍：为什么默认用 SQLite 而不是 MySQL？
 *
 * 这个靶场的定位是「任何人 clone 下来 5 秒内能看到漏洞」。
 * 如果依赖 MySQL，使用者要先装服务、建库、导数据、配账号 ——
 * 大量人会在这一步放弃，项目页面的访问量就浪费了。
 *
 * SQLite 是单文件数据库，PHP 自带 pdo_sqlite 扩展即可驱动，
 * 首次访问自动建库建表。UNION / 报错 / 盲注 / 堆叠（部分）等注入手法
 * 在 SQLite 上同样成立，教学效果不打折。
 *
 * 需要更真实的 MySQL 环境时，把 data/schema.mysql.sql 导入 MySQL，
 * 改下面的 DB_DRIVER 与 DSN 即可，SQL 语句已做兼容处理。
 *
 * ⚠️ 安全警告：本文件中的凭据是靶场演示用的假数据，不要据此设计任何真实系统。
 */

declare(strict_types=1);

// ------------------------------------------------------------------ 配置

/** 数据库驱动：sqlite | mysql */
define('DB_DRIVER', getenv('VULNLAB_DB') ?: 'sqlite');

/** SQLite 数据文件路径 */
define('DB_SQLITE_FILE', __DIR__ . '/data/vulnlab.db');

/** MySQL 连接参数（DB_DRIVER=mysql 时生效） */
define('DB_MYSQL_HOST', getenv('VULNLAB_MYSQL_HOST') ?: '127.0.0.1');
define('DB_MYSQL_PORT', (int) (getenv('VULNLAB_MYSQL_PORT') ?: 3306));
define('DB_MYSQL_NAME', getenv('VULNLAB_MYSQL_NAME') ?: 'vulnlab');
define('DB_MYSQL_USER', getenv('VULNLAB_MYSQL_USER') ?: 'root');
define('DB_MYSQL_PASS', getenv('VULNLAB_MYSQL_PASS') ?: 'root');

/** 站点标题 —— 各页面统一引用，避免硬编码散落各处 */
define('SITE_NAME', 'VulnLab');

/**
 * 「内网服务」的地址 —— SSRF 场景的攻击目标。
 *
 * 为什么不直接硬编码 127.0.0.1:8090：
 * SSRF 场景要求「服务端去请求另一个服务」，而这个地址**在不同部署方式下不一样**：
 *
 *   本机直接跑（php -S）  →  http://127.0.0.1:8090
 *   Docker Compose        →  http://vulnlab-internal   （容器名，不是 127.0.0.1）
 *
 * 在容器里写 127.0.0.1 会指向容器自己，SSRF 永远打不通 ——
 * 而且页面只会显示「请求失败（目标不可达）」，很难联想到是地址写错了。
 * 这类「部署方式变了但配置没跟着变」的问题，在真实项目里非常常见。
 */
define('INTERNAL_BASE', rtrim(getenv('VULNLAB_INTERNAL_BASE') ?: 'http://127.0.0.1:8090', '/'));

// ------------------------------------------------------------------ 数据

/**
 * 靶场种子数据。
 *
 * 注意 password 字段存的是假 MD5，secret 字段是「通关凭证」——
 * 只有成功注入才能读到，用于自我验证注入是否真的生效。
 * 这是靶场设计的通用做法：给一个可验证的、无害的目标。
 */
function seed_users(): array
{
    return [
        ['id' => 1, 'username' => 'admin', 'password' => '21232f297a57a5a743894a0e4a801fc3', 'email' => 'admin@vulnlab.local', 'role' => 'admin',  'secret' => 'VULNLAB{union_select_master}'],
        ['id' => 2, 'username' => 'alice', 'password' => '5f4dcc3b5aa765d61d8327deb882cf99', 'email' => 'alice@vulnlab.local', 'role' => 'user',   'secret' => 'nothing-here-for-alice'],
        ['id' => 3, 'username' => 'bob',   'password' => 'e10adc3949ba59abbe56e057f20f883e', 'email' => 'bob@vulnlab.local',   'role' => 'user',   'secret' => 'nothing-here-for-bob'],
        ['id' => 4, 'username' => 'carol', 'password' => '25d55ad283aa400af464c76d713c07ad', 'email' => 'carol@vulnlab.local', 'role' => 'auditor','secret' => 'nothing-here-for-carol'],
        ['id' => 5, 'username' => 'dave',  'password' => 'e99a18c428cb38d5f260853678922e03', 'email' => 'dave@vulnlab.local',  'role' => 'user',   'secret' => 'nothing-here-for-dave'],
    ];
}

// ------------------------------------------------------------------ 连接

/**
 * 获取 PDO 连接（单例）。
 *
 * 用 PDO 而不是 mysqli 的原因：PDO 的预处理接口更清晰，
 * 后面讲「参数化查询为什么能根治注入」时，代码对比更直观。
 */
function db(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    if (DB_DRIVER === 'mysql') {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            DB_MYSQL_HOST,
            DB_MYSQL_PORT,
            DB_MYSQL_NAME
        );
        $pdo = new PDO($dsn, DB_MYSQL_USER, DB_MYSQL_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        return $pdo;
    }

    $dir = dirname(DB_SQLITE_FILE);
    if (!is_dir($dir)) {
        mkdir($dir, 0777, true);
    }

    $pdo = new PDO('sqlite:' . DB_SQLITE_FILE, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA foreign_keys = ON');

    return $pdo;
}

/**
 * 首次访问时建表并灌入种子数据（幂等）。
 *
 * 把初始化放在运行时而不是「让你手动执行 SQL」，
 * 同样是为了「clone 下来就能跑」这个目标。
 */
function init_db_if_needed(): void
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;

    $pdo = db();

    if (DB_DRIVER === 'mysql') {
        $sql = 'CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL,
            password VARCHAR(128) NOT NULL,
            email VARCHAR(128) NOT NULL,
            role VARCHAR(32) NOT NULL,
            secret VARCHAR(255) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4';
    } else {
        $sql = 'CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            secret TEXT NOT NULL
        )';
    }

    try {
        $pdo->exec($sql);
    } catch (PDOException $e) {
        return; // 表已存在
    }

    $count = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    if ($count > 0) {
        return;
    }

    $stmt = $pdo->prepare(
        'INSERT INTO users (id, username, password, email, role, secret) VALUES (?, ?, ?, ?, ?, ?)'
    );
    foreach (seed_users() as $user) {
        $stmt->execute([
            $user['id'],
            $user['username'],
            $user['password'],
            $user['email'],
            $user['role'],
            $user['secret'],
        ]);
    }
}

// 所有页面引入本文件即完成初始化
init_db_if_needed();
