<?php
/**
 * 命令注入 · high 档 —— 修复对照
 *
 * 修复需要**两层**，缺一不可：
 *
 *   ① 输入校验（白名单）—— 确认输入「长得像 IP」
 *   ② 参数转义（escapeshellarg）—— 确保参数「不会被 shell 解释」
 *
 * ══════════════════════════════════════════════════════════════════
 * 为什么两层都要
 * ══════════════════════════════════════════════════════════════════
 *
 * **只有 ①（校验）**：校验逻辑本身可能被绕过。
 *   · 正则写漏了一种形式（IPv6 的压缩写法、域名里的下划线）
 *   · 校验用的函数和实际执行用的解析器不是同一个（经典的解析差异问题）
 *   · 以后有人改校验规则时手抖
 *
 * **只有 ②（转义）**：虽然 escapeshellarg 本身很可靠，但：
 *   · 它在 Windows 和 Linux 上的行为有细微差异（引号规则不同）
 *   · 如果哪天有人把命令改成别的方式（如 shell_exec 换成 exec 并自己拼参数）
 *     转义就可能被漏掉
 *
 * 而且这两层防的是**不同方向**的失败：
 *   ① 防的是「输入是不是意外的东西」（业务层面）
 *   ② 防的是「就算它是恶意的东西，也不能被执行」（语法层面）
 *
 * 这和 SQL 注入的修复是同一个思路：
 *   白名单校验 ≈ 检查参数格式     参数化查询 ≈ 让参数不参与语法解析
 *   两层叠加，而不是二选一。
 *
 * ══════════════════════════════════════════════════════════════════
 * 更彻底的做法
 * ══════════════════════════════════════════════════════════════════
 *
 * 最根本的修复是**根本不用 shell**：
 *
 *   PHP 的 `proc_open` / `exec` 配合数组形式的命令参数，
 *   可以让参数直接传给程序，完全绕开 shell 解析 —— 这才是治本。
 *
 *   // 不经过 shell，参数不会被解释
 *   $process = proc_open(['ping', '-c', '2', $ip], $descriptors, $pipes);
 *
 * 本档用 escapeshellarg 是因为它更通用（任何语言、任何平台都有对应做法），
 * 但如果你能选，优先选「不经过 shell」。
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
$audit = [];
$elapsed = 0.0;

/** 允许的主机形式：IPv4 / IPv6 / 域名（含短横线和点） */
function looks_like_host(string $value): bool
{
    if ($value === '' || strlen($value) > 253) {
        return false;
    }
    if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
        return true;   // IPv4 或 IPv6
    }
    // 域名：字母数字、点、短横线，不能以点或短横线开头结尾
    return (bool) preg_match('/^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/i', $value);
}

if ($submitted) {
    // ── 第 ① 层：白名单校验 ────────────────────────────────────
    if (!looks_like_host($ip)) {
        $error = '输入不合法：只允许 IPv4 / IPv6 地址或合法域名。';
        $audit[] = ['① 白名单校验', $ip, '✗ 拒绝'];
    } else {
        $audit[] = ['① 白名单校验', $ip, '✓ 通过'];

        // ── 第 ② 层：参数转义 ──────────────────────────────────
        //
        // escapeshellarg 做的事：给参数加上引号，并把参数内部的引号转义掉。
        // 这样即使输入里有 `;` `|` 换行，它们也只是**引号内的普通字符**，
        // shell 会把整个引号内容当成一个参数，不会去解释它。
        $safeIp = escapeshellarg($ip);
        $executedCommand = "ping {$countFlag} 2 {$safeIp}";

        // 展示转义前后的差异 —— 这是本档最直观的部分
        if ($safeIp !== $ip) {
            $audit[] = ['② 参数转义', "{$ip}  →  {$safeIp}", '✓ 已加引号并转义'];
        } else {
            $audit[] = ['② 参数转义', $safeIp, '✓ 原样（无特殊字符）'];
        }

        $started = microtime(true);
        $output = (string) @shell_exec($executedCommand . ' 2>&1');
        $elapsed = microtime(true) - $started;
    }
}

/** 对照实验 */
$attacks = [
    '127.0.0.1; whoami'          => '分号',
    '127.0.0.1 | whoami'         => '管道',
    "127.0.0.1\nwhoami"          => '换行符（medium 档的绕过点）',
    '127.0.0.1 $(whoami)'        => '命令替换',
    '127.0.0.1`whoami`'          => '反引号',
    '127.0.0.1 && cat /etc/passwd' => '逻辑与 + 读文件',
];
?>
<?php layout_header(
    '命令注入 · 难度 high（已修复）',
    '白名单校验 + 参数转义 —— 两层叠加，这一档打不动。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护：两层</h3>
  <div class="tbl-wrap" style="margin-top:10px">
    <table>
      <thead><tr><th style="width:24%">层</th><th style="width:30%">手段</th><th>挡住什么</th></tr></thead>
      <tbody>
        <tr>
          <td><b>① 白名单校验</b></td>
          <td><code>filter_var</code> + 域名正则</td>
          <td>不像 IP / 域名的输入（业务层面）</td>
        </tr>
        <tr>
          <td><b>② 参数转义</b></td>
          <td><code>escapeshellarg()</code></td>
          <td><b>即使校验被绕过，参数也不会被 shell 解释</b>（语法层面）</td>
        </tr>
      </tbody>
    </table>
  </div>

  <h3>关键代码</h3>
  <pre style="margin:0">if (!looks_like_host($ip)) { <span class="c">/* 拒绝 */</span> }              <span class="c">// ①</span>

$safeIp = escapeshellarg($ip);                              <span class="c">// ②</span>
$cmd = <span class="s">"ping {$countFlag} 2 {$safeIp}"</span>;</pre>

  <p style="margin:10px 0 0;font-size:14px;color:#065f46">
    注意：<b>输入内容没有被修改</b>，只是它在 shell 里不再被当作语法。
    和 SQL 参数化、XSS 输出编码是同一个道理。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="high.php">
    <input type="text" name="ip" value="<?= htmlspecialchars($ip) ?>"
           placeholder="把 low / medium 档成功的载荷粘进来" style="min-width:340px">
    <button type="submit">Ping</button>
  </form>
  <p class="hint">会被 ① 层直接拦下 —— 因为带 <code>;</code> 的字符串不像 IP 也不像域名。</p>
</div>

<?php if ($submitted): ?>
  <div class="card tight" style="margin-bottom:14px">
    <div style="font-size:13px;color:var(--muted);margin-bottom:10px">校验过程（逐层审计）</div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th style="width:24%">层</th><th style="width:46%">观察到的值</th><th>结果</th></tr></thead>
        <tbody>
          <?php foreach ($audit as [$layer, $value, $result]): ?>
            <tr>
              <td><?= htmlspecialchars($layer) ?></td>
              <td class="mono" style="word-break:break-all"><?= htmlspecialchars($value) ?></td>
              <?php /* 注意：这里不能用 str_starts_with() —— 它是 PHP 8.0 才有的函数，
                       而靶场声明兼容 PHP 7.2+（本机实际跑的是 7.3）。
                       用 PHP 8 的函数会导致 Fatal error，而且报错信息在页面里
                       可能只表现为「这一块内容整体消失」，不容易定位。 */ ?>
              <td style="color:<?= strpos($result, '✗') === 0 ? 'var(--danger)' : 'var(--ok)' ?>;font-weight:500">
                <?= htmlspecialchars($result) ?>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>

  <?php if ($error !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
    </div>
  <?php endif; ?>

  <?php if ($error === ''): ?>
    <?php render_code_board('服务端实际执行的命令', $executedCommand); ?>
    <div class="card">
      <h3 style="margin-top:0">命令输出</h3>
      <pre style="max-height:400px;overflow:auto"><?= command_output_html($output) ?></pre>
      <p class="hint">耗时 <?= number_format($elapsed, 3) ?> 秒</p>
    </div>
  <?php endif; ?>
<?php endif; ?>

<h2>对照实验：同一批载荷，三档的结果</h2>
<p class="sub" style="margin-bottom:12px">
  这些在 low 档全部得手、在 medium 档大部分得手，在 high 档全部被拦。
</p>
<div class="tbl-wrap">
  <table>
    <thead><tr>
      <th style="width:40%">载荷</th>
      <th style="width:26%">用的分隔符</th>
      <th>high 档结果</th>
    </tr></thead>
    <tbody>
      <?php foreach ($attacks as $attack => $note): ?>
        <tr>
          <td class="mono" style="word-break:break-all">
            <a href="?ip=<?= rawurlencode($attack) ?>"><?= nl2br(htmlspecialchars($attack)) ?></a>
          </td>
          <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          <td><span class="tag high">白名单拒绝</span></td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="card" style="margin-top:20px">
  <h3 style="margin-top:0">最彻底的修复：根本不用 shell</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    本档用 <code>escapeshellarg</code> 是因为它通用（任何语言都有对应做法）。
    但如果你能选，<b>优先选「不经过 shell」</b>：
  </p>
  <pre style="margin:0 0 10px">// 参数以【数组】形式传给程序，完全绕开 shell 解析
$process = proc_open(['ping', '-c', '2', $ip], $descriptors, $pipes);

// Python 里同理
subprocess.run(['ping', '-c', '2', ip])          // 安全
subprocess.run(f'ping -c 2 {ip}', shell=True)    // 危险</pre>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    <b>「不经过 shell」和「参数化查询」是同一类修复</b>：
    不是想办法把危险字符过滤掉，而是让危险内容<b>根本没有机会被解析</b>。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">修复要点总结</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>首选「不经过 shell」</b>：用数组形式传参（PHP <code>proc_open</code>、
      Python <code>subprocess.run(list)</code>、Java <code>ProcessBuilder</code>）。
    </li>
    <li>
      <b>必须用 shell 时，参数一律 <code>escapeshellarg</code></b>，
      不要自己写转义逻辑。
    </li>
    <li>
      <b>白名单校验要有，但不要把它当成唯一防线。</b>
      校验可能被绕过（解析差异、规则写漏），它和转义防的是不同方向的失败。
    </li>
    <li>
      <b>不要用黑名单过滤命令分隔符。</b>
      本档的 medium 已经演示了 —— shell 的元字符集合比你想到的多，
      而且不同 shell 还不一样。
    </li>
    <li>
      <b>能不用系统命令就不用。</b>
      很多场景有纯语言的实现（PHP 的 <code>gethostbyname</code>、
      <code>filter_var</code> 就能做 IP 校验，根本不需要 ping）。
      <b>消除调用，就消除了注入面。</b>
    </li>
    <li>
      <b>降权运行。</b>Web 进程不该以 root/Administrator 运行 ——
      这一条不能防注入，但能把注入的后果从「拿下服务器」压到「拿到一个低权账号」。
    </li>
  </ul>
</div>

<?php layout_footer(); ?>
