<?php
/**
 * SSRF · medium 档
 *
 * 漏洞成因：用**字符串黑名单**匹配危险地址 —— 和前面几个场景是同一个错误。
 *
 * `stripos($url, '127.0.0.1')` 这类检查的问题在于：
 * **同一个 IP 有无数种写法**，而字符串匹配只认其中一种。
 *
 *   http://127.0.0.1/      点分十进制（黑名单唯一认得的形式）
 *   http://127.1/          省略中间段 —— 多数系统会补成 127.0.0.1
 *   http://0x7f000001/     十六进制
 *   http://2130706433/     十进制整数
 *   http://017700000001/   八进制
 *   http://[::1]/          IPv6 回环
 *   http://127.0.0.1.nip.io/   通配 DNS（解析到 127.0.0.1）
 *
 * 黑名单只能列出作者想到的那几种写法，而 IP 的表示法是无穷的。
 *
 * **正确的方向是「解析之后校验」，而不是「匹配字符串」。**
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$url = isset($_GET['url']) ? (string) $_GET['url'] : '';
$submitted = ($url !== '');

$content = '';
$error = '';
$blockedBy = '';
$elapsed = 0.0;

// ------------------------------------------------------------------
// 漏洞点：字符串黑名单
//
// ⚠️ 注意这个黑名单【漏掉了 localhost】。
//
// 这不是我故意留的后门，而是真实世界里最常见的疏漏类型：
// 开发者想到了 127.0.0.1，却忘了 localhost 是它的等价写法。
// 类似的还有只写 10. 却忘了 172.16. / 192.168.，或者只拦 http 忘了 gopher。
//
// **黑名单的失败从来不是因为「写得不够努力」，而是因为它要求你穷举一个
// 你根本无法穷举的集合。** 本档的绕过点就在这里。
// ------------------------------------------------------------------
$blacklist = [
    '127.0.0.1', '0.0.0.0',
    '192.168.', '10.', '172.16.', '172.17.',
    'file://', 'gopher://', 'dict://',
];

if ($submitted) {
    foreach ($blacklist as $bad) {
        if (stripos($url, $bad) !== false) {
            $blockedBy = $bad;
            break;
        }
    }

    if ($blockedBy !== '') {
        $error = '请求被拦截：URL 中包含被禁止的字符串「' . $blockedBy . '」';
    } else {
        $started = microtime(true);
        $context = stream_context_create([
            'http' => ['method' => 'GET', 'timeout' => 5, 'ignore_errors' => true],
            'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
        ]);
        $content = @file_get_contents($url, false, $context);
        $elapsed = microtime(true) - $started;

        if ($content === false) {
            $error = '请求失败（目标不可达或协议不支持）';
        }
    }
}

/** 绕过示例 —— 全部指向同一个 127.0.0.1
 *
 * 端口从 INTERNAL_BASE 里取，这样换部署方式（Docker / 本机）时不用改这一堆 URL。
 * 主机名部分保持 127.0.0.1 的各种变形 —— 本档演示的就是「黑名单只认得字面量」。
 */
$internalPort = parse_url(INTERNAL_BASE, PHP_URL_PORT) ?: 80;
$probePath = '/internal/inner-service.php';

// ⚠️ 这里不能用箭头函数 `fn() => ...` —— 它是 **PHP 7.4** 才引入的语法，
// 而靶场声明兼容 PHP 7.2+（本机实际跑 7.3）。
// 用传统闭包最稳：兼容性没有下界问题。
$v = static function (string $host) use ($internalPort, $probePath): string {
    return "http://{$host}:{$internalPort}{$probePath}";
};

$bypasses = [
    $v('localhost')    => '★ 等价写法：localhost 就是 127.0.0.1，但黑名单漏了它',
    $v('127.0.0.1')    => '对照组：这个会被拦下',
    $v('127.1')        => '省略段写法 —— Linux 有效，本机是 Windows 所以连不通',
    $v('0x7f000001')   => '十六进制 —— 同上，平台相关',
    $v('2130706433')   => '十进制 —— 同上，平台相关',
];
?>
<?php layout_header(
    'SSRF · 难度 medium',
    '字符串黑名单 —— 它只认得 IP 的其中一种写法。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$blacklist = [<span class="s">'127.0.0.1'</span>, <span class="s">'localhost'</span>, <span class="s">'192.168.'</span>, <span class="s">'10.'</span>, <span class="s">'file://'</span>, ...];

foreach ($blacklist as $bad) {
    if (stripos($url, $bad) !== false) { <span class="c">/* 拦截 */</span> }
}</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    和 low 档一样读到 <code>/internal/inner-service.php</code>，
    但这次不能直接写 <code>127.0.0.1</code>。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="medium.php">
    <input type="text" name="url"
           value="<?= htmlspecialchars($url) ?>"
           placeholder="换一种写法表示同一个地址"
           style="min-width:420px">
    <button type="submit">发起请求</button>
  </form>
</div>

<?php if ($submitted): ?>
  <?php if ($blockedBy !== ''): ?>
    <div class="card tight" style="background:var(--warn-soft);border-color:#fde68a;margin-bottom:14px">
      <div style="font-size:13px;color:#92400e;margin-bottom:8px">过滤器命中</div>
      <div class="kv"><b>被拦原因</b><span class="mono">URL 含字符串「<?= htmlspecialchars($blockedBy) ?>」</span></div>
      <p style="margin:8px 0 0;font-size:13px;color:#92400e">
        注意：它只判断了<b>字符串</b>，没有判断这个 URL <b>实际会连到哪里</b>。
      </p>
    </div>
  <?php endif; ?>

  <?php if ($error !== '' && $blockedBy === ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
    </div>
  <?php endif; ?>

  <?php if ($blockedBy === '' && $content !== false && $content !== ''): ?>
    <?php render_code_board(
        '过滤器放行了，服务端实际请求了什么',
        "URL: {$url}\n耗时: " . number_format($elapsed, 3) . " 秒\n\n"
        . "过滤器看到的是字符串，服务器看到的是解析后的地址 ——\n"
        . "这两者之间的差异，就是绕过的空间。"
    ); ?>
    <div class="card">
      <h3 style="margin-top:0">响应内容</h3>
      <pre style="max-height:400px;overflow:auto"><?= htmlspecialchars(substr((string) $content, 0, 5000)) ?></pre>
    </div>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">同一个地址的不同写法</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    下面这些全部指向 <code>127.0.0.1</code> —— 黑名单只认得第一种。
  </p>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:58%">URL</th><th>为什么能绕过</th></tr></thead>
      <tbody>
        <?php foreach ($bypasses as $b => $note): ?>
          <tr>
            <td class="mono" style="word-break:break-all">
              <a href="?url=<?= rawurlencode($b) ?>"><?= htmlspecialchars($b) ?></a>
            </td>
            <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>

<div class="card">
  <h3 style="margin-top:0">为什么字符串匹配注定失败</h3>
  <pre style="margin:0">http://<span class="v">127.0.0.1</span>/          ← 黑名单认得
http://<span class="v">127.1</span>/              ← 省略段，补零后等价
http://<span class="v">0x7f000001</span>/       ← 十六进制
http://<span class="v">2130706433</span>/       ← 十进制整数
http://<span class="v">017700000001</span>/   ← 八进制
http://<span class="v">[::ffff:127.0.0.1]</span>/ ← IPv4 映射的 IPv6
http://<span class="v">127.0.0.1.nip.io</span>/ ← 通配 DNS 解析回 127.0.0.1
http://<span class="v">spoofed.example</span>/     ← 攻击者控制的域名，A 记录指向 127.0.0.1</pre>
  <p class="hint">
    最后两条尤其关键：<b>它们连 IP 字面量都不是</b>，
    任何针对 IP 字符串的检查都拦不住。
    <b>唯一可靠的做法是解析出真实 IP 之后再判断。</b>
  </p>

  <div style="margin-top:14px;padding:12px 14px;background:var(--warn-soft);border-radius:8px;font-size:13px;color:#92400e;line-height:1.8">
    <b>关于平台差异（本靶场实测结论）</b><br>
    上面这些写法<b>不是在所有系统上都有效</b>。
    本靶场运行在 Windows 上，实测只有 <code>127.0.0.1</code> 和 <code>localhost</code>
    能连通；<code>127.1</code>、十六进制、八进制这些写法 Windows 的解析器直接不支持
    （Linux 的 <code>inet_aton</code> 则支持）。
    <br><br>
    这个差异本身也值得记住：<b>「绕过是否有用」取决于目标环境</b>。
    同一个 payload 在 Linux 上通、Windows 上不通 ——
    所以真实渗透中，先判断目标系统类型，再决定试哪些写法。
    本档能稳定演示的绕过点是 <code>localhost</code>，因为它在各平台都有效。
  </div>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>过滤器检查的是「URL 长什么样」，还是「URL 会连到哪里」？</li>
    <li>同一个 IPv4 地址有几种写法？试着查一下 inet_aton 的解析规则。</li>
    <li>如果换个域名也能指向 127.0.0.1，黑名单还有意义吗？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/ssrf.md</code>。</p>
</div>

<?php layout_footer(); ?>
