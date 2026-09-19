<?php
/**
 * CSRF · medium 档 —— 用 Referer 判断请求来源
 *
 * 防护方式：检查 `Referer` 头里是否包含本站的 host。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 这个防护有两个独立的绕过点，而且都不需要「破解」任何东西
 * ══════════════════════════════════════════════════════════════════
 *
 * ── 绕过一：Referer 是「客户端自愿提供的」 ──
 *
 * 代码里写着：
 *
 *     if ($referer === '') {
 *         // 没有 Referer —— 大概是用户直接访问的，放行
 *     }
 *
 * 这个推断的前提是「攻击者没法不发 Referer」。但事实是：
 *
 *     <meta name="referrer" content="no-referrer">
 *
 * **攻击者在自己页面的 `<head>` 里加这一行，浏览器发送的请求就完全不带 Referer。**
 *
 * 所以「空 Referer 放行」不是「兼容性考虑」，而是一个**完整的绕过**：
 * 攻击者既能控制自己页面长什么样，就当然能决定要不要带上 Referer。
 *
 * 一句话：
 * **Referer 属于「请求方可以自愿提供、也可以自愿不提供」的信息，
 *  服务端不能把它当作强制性的证据。**
 *
 * ── 绕过二：子串匹配没有边界 ──
 *
 * 代码用的是：
 *
 *     strpos($referer, $host) !== false
 *
 * 这是「包含」判断，不是「相等」判断。于是：
 *
 *     目标是 bank.com
 *     攻击者注册 bank.com.evil.com
 *     浏览器自动填的 Referer 就是 http://bank.com.evil.com/...
 *                            ↑ 里面确实包含 "bank.com"
 *
 * **注意这个绕过不需要伪造任何请求头** —— 攻击者只是买了个域名，
 * 浏览器诚实地填上了真实的 Referer，检查却通过了。
 *
 * 这类「包含 vs 相等」的错误在整个靶场里反复出现
 * （SSRF 的 `localhost` 绕过、命令注入的黑名单漏项…），
 * 根本原因都是：**用「出现了某个片段」代替了「它就是这个东西」。**
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/state.php';

if (isset($_GET['reset'])) {
    csrf_reset();
    header('Location: ' . basename(__FILE__));
    exit;
}

$state = csrf_load();
$submitted = false;
$changed = false;
$receivedEmail = '';
$blockedReason = '';
$referer = (string) ($_SERVER['HTTP_REFERER'] ?? '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submitted = true;
    $receivedEmail = isset($_POST['email']) ? trim((string) $_POST['email']) : '';

    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');

    // ------------------------------------------------------------------
    // 防护：检查 Referer
    //
    // 两个问题都在这一段里：
    //   ① 空 Referer 直接放行 —— 而攻击者的页面可以按需去掉 Referer
    //   ② 用的是 strpos 子串匹配，没有做「边界」判断
    // ------------------------------------------------------------------
    if ($referer === '') {
        $allow = true;   // ← 问题一
    } elseif (strpos($referer, $host) !== false) {
        $allow = true;   // ← 问题二：包含即可，不要求相等
    } else {
        $allow = false;
        $blockedReason = 'Referer 不包含本站 host（' . $host . '）';
    }

    if ($allow && $receivedEmail !== '') {
        $state['email'] = $receivedEmail;
        csrf_save($state);
        $changed = true;
    }
}

$host = (string) ($_SERVER['HTTP_HOST'] ?? '');
?>
<?php layout_header(
    'CSRF · 难度 medium',
    '用 Referer 判断来源，却把它当成了「攻击者无法控制」的信息。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$host = $_SERVER[<span class="s">'HTTP_HOST'</span>];
$referer = $_SERVER[<span class="s">'HTTP_REFERER'</span>];

<span class="k">if</span> ($referer === <span class="s">''</span>) {
    $allow = <span class="f">true</span>;                                    <span class="c">// ← 绕过点一</span>
} <span class="k">elseif</span> (<span class="v">strpos</span>($referer, $host) !== <span class="f">false</span>) {
    $allow = <span class="f">true</span>;                                    <span class="c">// ← 绕过点二</span>
} <span class="k">else</span> {
    $allow = <span class="f">false</span>;
}</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    同样是改掉 <code>alice</code> 的邮箱。这次请求会被检查 Referer ——
    找到办法让检查通过。
  </p>
</div>

<?php render_csrf_state($state, $referer !== ''
    ? '上一次请求带的 Referer：<code>' . htmlspecialchars($referer) . '</code>'
    : '上一次请求<b>没有带</b> Referer。'); ?>

<div class="card">
  <h3 style="margin-top:0">正常功能的表单</h3>
  <form method="post" action="medium.php">
    <div class="row">
      <label style="min-width:90px">绑定邮箱</label>
      <input type="text" name="email" style="flex:1;font-family:var(--mono)"
             value="<?= htmlspecialchars($state['email']) ?>">
    </div>
    <div class="row">
      <button type="submit">保存</button>
      <a href="?reset=1" style="margin-left:10px;font-size:13px">重置场景</a>
    </div>
  </form>
  <?php if ($submitted): ?>
    <p class="hint" style="margin:10px 0 0">
      上一次请求：<b><?= $changed ? '已修改' : '被拒绝' ?></b>
      <?php if ($blockedReason !== ''): ?>
        —— <?= htmlspecialchars($blockedReason) ?>
      <?php endif; ?>
    </p>
  <?php endif; ?>
</div>

<div class="card">
  <h3 style="margin-top:0">两个绕过点，两个都不需要「破解」</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:22%">绕过</th><th style="width:34%">做法</th><th>为什么有效</th></tr></thead>
      <tbody>
        <tr>
          <td><b>去掉 Referer</b></td>
          <td class="mono">在攻击页面的 &lt;head&gt; 里加<br>&lt;meta name="referrer" content="no-referrer"&gt;</td>
          <td>
            <b>Referer 是客户端自愿提供的信息</b> ——
            攻击者控制着自己页面的 HTML，当然也就能决定要不要带上它。<br>
            「空 Referer 放行」等于把门开着。
          </td>
        </tr>
        <tr>
          <td><b>域名包含</b></td>
          <td class="mono">目标是 <?= htmlspecialchars($host) ?><br>
            攻击者用「名字里含这个串」的域名</td>
          <td>
            <code>strpos</code> 判断的是「<b>包含</b>」，不是「<b>相等</b>」。<br>
            真实场景：目标是 <code>bank.com</code>，攻击者注册
            <code>bank.com.evil.com</code>，浏览器自动填的 Referer 就带着这个子串。<br>
            <b>攻击者不需要伪造任何请求头</b>。
          </td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="hint">
    真实场景里第二个绕过更值得警惕 —— 它不需要攻击者做任何「技术性」的事，<br>
    只是买了个域名而已。而校验代码里那句 <code>strpos(...) !== false</code>
    看起来完全正常。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>这个检查依赖的那个请求头，是谁填的？填的人能不能选择不填？</li>
    <li>代码在 Referer 为空时选择了什么？这个选择合理吗？</li>
    <li><code>strpos($a, $b) !== false</code> 判断的是「包含」还是「相等」？两者的差别在哪？</li>
    <li>如果目标是 <code>127.0.0.1:8080</code>，什么样的 Referer 能包含这个串、却又不是你自己的站点？</li>
  </ul>
  <p class="hint">
    靶场的 host 是 <code><?= htmlspecialchars($host) ?></code>，
    这种形式的「域名」没法真的注册 —— 所以演示时用 curl / Burp
    直接构造 Referer 头即可，效果等价。
  </p>
</div>

<?php layout_footer(); ?>
