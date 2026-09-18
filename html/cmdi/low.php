<?php
/**
 * 命令注入 · low 档
 *
 * 漏洞成因：把用户输入**直接拼进系统命令**，且命令经过 shell 解释。
 *
 * 这是「数据被当成代码」的第四种形态（前三种是 SQL、HTML、上传的文件）：
 *
 *   SQL 注入   数据被当成 SQL 语法     → 数据库执行
 *   XSS        数据被当成 HTML 语法    → 浏览器执行
 *   文件上传   数据被当成可执行文件     → Web 服务器执行
 *   命令注入   数据被当成 shell 命令    → 操作系统执行   ← 这个最直接
 *
 * 为什么它是最危险的一类：
 * 前三者还要绕一层（构造 SQL、构造标签、找可访问路径），
 * 而命令注入**直接就拿到了操作系统权限**。
 * 一个 `; whoami` 就能确认，一个反弹 shell 就能接管。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

/** ping 的参数在不同平台不一样 —— 靶场要能在 Windows 和 Linux 上跑 */
$isWindows = stripos(PHP_OS_FAMILY, 'Windows') !== false;
$countFlag = $isWindows ? '-n' : '-c';

$ip = isset($_GET['ip']) ? (string) $_GET['ip'] : '';
$submitted = ($ip !== '');

$output = '';
$executedCommand = '';
$elapsed = 0.0;

if ($submitted) {
    // ------------------------------------------------------------------
    // 漏洞点：字符串拼接 + 交给 shell 解释
    //
    // shell_exec 会把整个字符串交给系统 shell（Windows 是 cmd，Linux 是 sh），
    // 而 shell 把 `;` `|` `&` 当成命令分隔符 ——
    // 于是用户输入里带上这些符号，就能追加自己的命令。
    //
    // 关键认知：**危险的不是「用户输入了特殊字符」，而是「用户输入被 shell 解释了」。**
    // 这跟 SQL 注入是同构的：危险的不是引号，而是数据参与了语法解析。
    // ------------------------------------------------------------------
    $executedCommand = "ping {$countFlag} 2 {$ip}";

    $started = microtime(true);
    $output = (string) @shell_exec($executedCommand . ' 2>&1');
    $elapsed = microtime(true) - $started;
}

/** 演示载荷 */
$samples = [
    '127.0.0.1; whoami'          => '分号：顺序执行两条命令',
    '127.0.0.1 | whoami'         => '管道：把前一条的输出交给后一条',
    '127.0.0.1 && whoami'        => '逻辑与：前一条成功才执行后一条',
    '127.0.0.1 & whoami'         => '后台执行：两条命令并行',
    '127.0.0.1; cat /etc/passwd' => '读取文件（Linux）',
    '127.0.0.1; dir'             => '列目录（Windows）',
];
?>
<?php layout_header(
    '命令注入 · 难度 low',
    '用户输入被拼进系统命令，且命令行经过 shell 解释 —— 于是能追加命令。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    命令注入的后果是<b>直接拿到操作系统命令执行权限</b> ——
    比信息泄露类漏洞严重得多。<br>
    只在本地靶场练习；<b>不要尝试任何反弹 shell 之类的持久化操作</b>，
    那会影响你本机的安全状态。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">零防护 —— 直接拼接：</p>
  <pre style="margin:10px 0 0">$executedCommand = <span class="s">"ping {$countFlag} 2 {$ip}"</span>;
$output = shell_exec($executedCommand);</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    让服务器执行 <code>whoami</code> 并看到回显。
    页面会把<b>服务端实际执行的命令</b>摊开给你看 —— 对比「你输入的」和
    「它拼出来执行的」，漏洞成因就很清楚了。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="low.php">
    <input type="text" name="ip" value="<?= htmlspecialchars($ip) ?>"
           placeholder="127.0.0.1" style="min-width:340px">
    <button type="submit">Ping</button>
  </form>
  <p class="hint">输入一个 IP，服务端会 ping 它。</p>
</div>

<?php if ($submitted): ?>
  <?php
  render_code_board(
      '服务端实际执行的命令',
      $executedCommand . "\n\n"
      . "你的输入: {$ip}\n"
      . "拼接结果: ping {$countFlag} 2 {$ip}\n\n"
      . "注意：这条命令是交给系统 shell 执行的，\n"
      . "而 shell 会把 ; | && & 当成【命令分隔符】。"
  );
  ?>

  <div class="card">
    <h3 style="margin-top:0">命令输出</h3>
    <pre style="max-height:400px;overflow:auto"><?= command_output_html($output) ?></pre>
    <p class="hint">耗时 <?= number_format($elapsed, 3) ?> 秒</p>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">可用载荷</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    下面这些分隔符在 shell 里都表示「一条命令结束，另一条开始」。
  </p>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:44%">载荷</th><th>说明</th></tr></thead>
      <tbody>
        <?php foreach ($samples as $payload => $note): ?>
          <tr>
            <td class="mono" style="word-break:break-all">
              <a href="?ip=<?= rawurlencode($payload) ?>"><?= htmlspecialchars($payload) ?></a>
            </td>
            <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <p class="hint">
    点击即可填入表单。注意 <code>;</code> 和 <code>|</code> 的区别：
    前者是「接着执行」，后者是「把前一条的输出交给后一条」。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">为什么它和 SQL 注入是同一类问题</h3>
  <pre style="margin:0">SQL 注入    输入 → 拼进 SQL 语句  → 数据库解析 → 执行 SQL
命令注入    输入 → 拼进 shell 命令 → shell 解析  → 执行命令
XSS        输入 → 拼进 HTML     → 浏览器解析 → 执行脚本

三者都是「数据进入了代码的位置」。
区别只在于【谁来解析】—— 数据库 / shell / 浏览器。

所以修复思路也一致：不要让数据参与语法解析。
命令注入的做法是把参数单独传给程序（不经过 shell），见 high 档。</pre>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>服务端把整条命令交给谁执行了？（注意是 <code>shell_exec</code> 而不是 <code>exec</code>）</li>
    <li>在 shell 的语法里，哪些符号表示「命令结束」？</li>
    <li>你输入的内容，和服务端最终执行的命令，中间隔了几层解析？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/cmdi.md</code>。</p>
</div>

<?php layout_footer(); ?>
