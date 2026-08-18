<?php
/**
 * 源码查看器。
 *
 * 靶场的标配功能，但这里顺便演示一个真实世界的高频漏洞：
 * **任意文件读取（路径穿越）**。
 *
 * 下面这段代码做了三层防护，正好是「怎么写才安全」的范例：
 *   1. realpath() 消解 ../ 与符号链接，得到真实绝对路径
 *   2. 前缀校验确保解析后的路径仍在白名单目录内
 *   3. 扩展名白名单，防止读取 .db / .ini 等非源码文件
 *
 * 少任何一层都会出问题：
 *   - 只做第 2 层 → 符号链接可以绕过（realpath 会解析掉）
 *   - 只做第 1 层 → ../ 被消解了但没有边界检查，仍能读到目录外
 *   - 只做第 3 层 → 后缀合法但目录不对，照样能读
 *
 * ⚠️ 注意：本文件本身**故意是安全的**。本站是漏洞靶场，
 * 但靶场自身的代码不该有漏洞 —— 否则就变成「用漏洞来教安全」了。
 */

declare(strict_types=1);

require __DIR__ . '/config.php';
require __DIR__ . '/lib/layout.php';

/** 允许查看的文件后缀 —— 白名单而非黑名单 */
const ALLOWED_EXTENSIONS = ['php', 'inc', 'html', 'js', 'css', 'sql'];

$requested = isset($_GET['file']) ? (string) $_GET['file'] : 'index.php';
$baseDir = __DIR__;
$error = '';
$resolved = '';
$source = '';

// 第 1 层：消解路径（处理 ../ 与符号链接）
$candidate = realpath($baseDir . DIRECTORY_SEPARATOR . $requested);

if ($candidate === false) {
    $error = '文件不存在：' . htmlspecialchars($requested);
} else {
    // 第 2 层：边界校验。注意这里比较的是 realpath 之后的路径，
    // 否则 `html/../html/../etc/passwd` 这类变形会绕过前缀匹配。
    $normalizedBase = rtrim(str_replace('\\', '/', $baseDir), '/');
    $normalizedTarget = str_replace('\\', '/', $candidate);

    if (strpos($normalizedTarget, $normalizedBase . '/') !== 0) {
        $error = '拒绝访问：目标文件不在允许的目录内。';
    } else {
        // 第 3 层：扩展名白名单
        $extension = strtolower(pathinfo($candidate, PATHINFO_EXTENSION));
        if (!in_array($extension, ALLOWED_EXTENSIONS, true)) {
            $error = '拒绝访问：不支持查看 .' . htmlspecialchars($extension) . ' 文件。';
        } else {
            $resolved = $candidate;
            $source = (string) file_get_contents($candidate);
        }
    }
}

$relative = $resolved !== '' ? str_replace('\\', '/', substr($resolved, strlen($baseDir) + 1)) : '';
?>
<?php layout_header('源码查看', '看懂代码再动手 —— 先理解漏洞为什么存在，再考虑怎么利用。'); ?>

<div class="card tight">
  <form class="inline" method="get" action="source.php">
    <input type="text" name="file" value="<?= htmlspecialchars($requested) ?>"
           placeholder="例如 sqli/low.php">
    <button type="submit">查看</button>
  </form>
  <p class="hint">
    可查看范围：<code>html/</code> 目录下的
    <?= htmlspecialchars(implode(' / ', ALLOWED_EXTENSIONS)) ?> 文件。
  </p>
</div>

<?php if ($error !== ''): ?>
  <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
    <b style="color:var(--danger)"><?= $error ?></b>
  </div>
<?php else: ?>
  <div class="card tight" style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
    <span class="mono" style="font-size:13px;color:var(--muted)">
      html/<?= htmlspecialchars($relative) ?>
    </span>
    <span class="tag"><?= count(explode("\n", $source)) ?> 行</span>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <?php highlight_file($resolved); ?>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">顺带一提：这段代码为什么是安全的</h3>
  <p style="margin:0;font-size:14px;color:var(--muted);line-height:1.9">
    任意文件读取是真实世界里的高频漏洞，「源码查看器」这类功能是重灾区。
    上面的实现用了三层防护：<br>
    <b>① realpath 消解</b> —— 把 <code>../../etc/passwd</code> 折叠成真实绝对路径，
    否则任何字符串过滤都能被 <code>....//</code> 之类的变形绕过。<br>
    <b>② 目录边界校验</b> —— 折叠之后才判断「是否还在白名单目录内」，
    顺序反了就没用。<br>
    <b>③ 扩展名白名单</b> —— 白名单优于黑名单，因为黑名单永远列不全。
  </p>
</div>

<?php layout_footer(); ?>
