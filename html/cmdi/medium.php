<?php
/**
 * 命令注入 · medium 档
 *
 * 漏洞成因：用**字符黑名单**过滤命令分隔符 —— 和前面三个场景是同一个错误。
 *
 * shell 的命令分隔符远不止 `;` `|` `&` 三个：
 *
 *   ;       顺序执行
 *   |       管道
 *   &       后台执行
 *   && ||   逻辑与/或
 *   换行符   ← 它也是命令分隔符！最容易被漏掉
 *   $(...)  命令替换
 *   `...`   命令替换（反引号）
 *   > >> <  重定向
 *
 * 本档的黑名单堵了前四个和命令替换，**唯独漏了换行符**。
 * 而换行在 HTTP 请求里只需要写 `%0a`。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$isWindows = stripos(PHP_OS_FAMILY, 'Windows') !== false;
$countFlag = $isWindows ? '-n' : '-c';

$ip = isset($_GET['ip']) ? (string) $_GET['ip'] : '';
$submitted = ($ip !== '');

$output = '';
$error = '';
$executedCommand = '';
$blockedBy = '';
$elapsed = 0.0;

if ($submitted) {
    // ------------------------------------------------------------------
    // 漏洞点：黑名单**漏掉了 `&`**
    //
    // 这不是随手写的漏项，而是真实世界里最常见的一种疏漏：
    // 开发者在 Linux 上开发、测试，脑子里想的是 Unix shell 的分隔符
    // （`;` `|` `` ` `` `$`），于是黑名单照这个思路写 ——
    // 但**漏掉了 Windows cmd 最常用的 `&`**。
    //
    // 而 `&` 在 Linux 的 sh 里同样有效（后台执行），
    // 所以这个漏项**在两个平台上都能被利用**。
    //
    // 更根本的问题仍然是：黑名单在原理上不可能穷举完备 ——
    // shell 的元字符集合是由 shell 的语法定义的，而且不同 shell 还不一样。
    // ------------------------------------------------------------------
    $blacklist = [';', '|', '$', '`', '>', '<'];

    foreach ($blacklist as $bad) {
        if (strpos($ip, $bad) !== false) {
            $blockedBy = $bad;
            break;
        }
    }

    if ($blockedBy !== '') {
        $error = '请求被拦截：输入中包含被禁止的字符「' . $blockedBy . '」';
    } else {
        $executedCommand = "ping {$countFlag} 2 " . $ip;

        $started = microtime(true);
        $output = (string) @shell_exec($executedCommand . ' 2>&1');
        $elapsed = microtime(true) - $started;
    }
}

/** 绕过示例 */
$bypasses = [
    '127.0.0.1 & whoami'     => '★ 单个 & —— 黑名单漏掉了它（Windows cmd 的主要分隔符）',
    '127.0.0.1 && whoami'    => '逻辑与：前一条成功才执行后一条',
    '127.0.0.1 & whoami & echo ok' => '连续追加多条命令',
    '127.0.0.1; whoami'      => '对照组：分号会被拦下',
    '127.0.0.1 | whoami'     => '对照组：管道会被拦下',
];
?>
<?php layout_header(
    '命令注入 · 难度 medium',
    '字符黑名单 —— 它列出了一批分隔符，但 shell 的分隔符不止这些。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    命令注入直接等于操作系统命令执行权限。仅限本地靶场练习，
    不要做任何持久化操作。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$blacklist = [<span class="s">';'</span>, <span class="s">'|'</span>, <span class="s">'$'</span>, <span class="s">'`'</span>, <span class="s">'&gt;'</span>, <span class="s">'&lt;'</span>];
<span class="c">//                        ↑ 注意这里没有 &</span>

foreach ($blacklist as $bad) {
    if (strpos($ip, $bad) !== false) { <span class="c">/* 拦截 */</span> }
}</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    和 low 档一样执行 <code>whoami</code>，但这次不能用上面那些符号。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="medium.php">
    <input type="text" name="ip" value="<?= htmlspecialchars($ip) ?>"
           placeholder="换一种方式让 shell 断句" style="min-width:340px">
    <button type="submit">Ping</button>
  </form>
</div>

<?php if ($blockedBy !== ''): ?>
  <div class="card tight" style="background:var(--warn-soft);border-color:#fde68a;margin-bottom:14px">
    <div style="font-size:13px;color:#92400e;margin-bottom:8px">过滤器命中</div>
    <div class="kv"><b>被拦原因</b><span class="mono">输入含字符「<?= htmlspecialchars($blockedBy) ?>」</span></div>
    <p style="margin:8px 0 0;font-size:13px;color:#92400e">
      它检查的是<b>你输入里有没有这些字符</b>，而不是
      <b>shell 会怎么解析你的输入</b> —— 这两者的差集就是绕过的空间。
    </p>
  </div>
<?php endif; ?>

<?php if ($submitted && $blockedBy === ''): ?>
  <?php
  render_code_board(
      '服务端实际执行的命令',
      $executedCommand . "\n\n"
      . "提示：如果你用的是 %0a，命令里其实已经有一条换行 ——\n"
      . "上面这段显示的是【解码后】的样子，而 shell 看到的正是这个样子。\n"
      . "也就是说：shell 把换行当成了「命令结束」。"
  );
  ?>
  <div class="card">
    <h3 style="margin-top:0">命令输出</h3>
    <pre style="max-height:400px;overflow:auto"><?= command_output_html($output) ?></pre>
    <p class="hint">耗时 <?= number_format($elapsed, 3) ?> 秒</p>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">这里真正值得记住的：黑名单是「按平台经验」写出来的</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    本档的黑名单禁了 <code>;</code> <code>|</code> <code>$</code> <code>`</code>
    <code>&gt;</code> <code>&lt;</code>，<b>唯独漏了 <code>&amp;</code></b>。
  </p>
  <div class="tbl-wrap" style="margin-bottom:12px">
    <table>
      <thead><tr><th style="width:22%">分隔符</th><th style="width:30%">Unix sh</th><th>Windows cmd</th></tr></thead>
      <tbody>
        <tr><td class="mono">;</td><td>顺序执行</td><td>不是分隔符（会被当成普通字符）</td></tr>
        <tr><td class="mono">|</td><td>管道</td><td>管道</td></tr>
        <tr><td class="mono">&amp;</td><td>后台执行</td><td><b>顺序执行（主要分隔符）</b></td></tr>
        <tr><td class="mono">&amp;&amp;</td><td>逻辑与</td><td>逻辑与</td></tr>
        <tr><td class="mono">换行符</td><td><b>顺序执行</b></td><td>不是分隔符</td></tr>
        <tr><td class="mono">$( )</td><td>命令替换</td><td>不支持</td></tr>
      </tbody>
    </table>
  </div>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    <b>看出问题了吗：两个平台的分隔符集合并不相同。</b>
    开发者在 Linux 上开发测试，黑名单自然照 Unix 的思路写 ——
    于是漏掉了 Windows 上最常用的 <code>&amp;</code>。
  </p>
  <p class="hint">
    本档可以实测：<code>&amp;</code> 能绕过、<code>;</code> 会被拦。
    <br>
    而 <b>换行符这条绕过在 Windows 上不成立</b>（Linux 上有效）——
    这又是一个「payload 有效性依赖目标环境」的例子，
    和 SSRF 场景里 IP 变形写法的平台差异是同一类问题。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">可用载荷</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:46%">载荷</th><th>说明</th></tr></thead>
      <tbody>
        <?php foreach ($bypasses as $payload => $note): ?>
          <tr>
            <td class="mono" style="word-break:break-all">
              <a href="?ip=<?= htmlspecialchars($payload, ENT_QUOTES) ?>"><?= htmlspecialchars($payload) ?></a>
            </td>
            <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <p class="hint">
    表格里的 <code>%0a</code> 是 URL 编码的换行符 ——
    在地址栏里直接打不出来，必须编码。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>黑名单里有哪几个字符？把它们列出来，然后问：<b>shell 只用这些符号断句吗？</b></li>
    <li>在终端里敲命令时，你按回车会发生什么？那个「回车」在 shell 眼里是什么？</li>
    <li>URL 里怎么表示一个换行符？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/cmdi.md</code>。</p>
</div>

<?php layout_footer(); ?>
