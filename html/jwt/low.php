<?php
/**
 * JWT · low 档 —— 接受 alg:none
 *
 * 漏洞成因：代码「支持」`alg: none`，也就是**不校验签名**。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 这个漏洞的形状，和前面几个场景都不一样
 * ══════════════════════════════════════════════════════════════════
 *
 * 前面几个场景的绕过，都是「过滤器没想到某种写法」——
 * SQL 的 `ununionion`、LFI 的 `....//`、反序列化的 `cache` 小写、
 * XXE 的外部 DTD。它们的共同点是：**防护想拦，但没拦全**。
 *
 * 这一档不是。它的代码**明确地、有意识地**放行了 alg:none ——
 * 也就是说，防护并不存在，只是看起来存在。
 *
 * ── 为什么会有人这么写 ──
 *
 * 因为 `alg: none` 是 JWT 规范里**合法**的一种算法，含义是
 * 「这个 token 没有签名」。它的设计初衷是给「已经在可信通道里传输」
 * 的场景用的（比如服务内部、TLS 双向认证之后）。
 *
 * 于是很自然的写法就是：
 *
 *     if (header.alg === 'none') {
 *         // 规范说这种情况没有签名，那就没什么可校验的
 *         return 通过;
 *     }
 *
 * 逻辑上没错 —— **确实没有签名可校验**。但结论错了：
 * 「没有签名可校验」的正确处理是**拒绝这个 token**，
 * 而不是「那就算它通过」。
 *
 * ── 一句话概括 ──
 *
 * **「我无法验证它」不等于「它是可信的」。**
 *
 * 这跟前面几个场景是不同层面的问题：前面是「防不住」，
 * 这里是「把不设防当成了合规」。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/jwt.php';

$action = isset($_POST['action']) ? (string) $_POST['action'] : '';
$token = isset($_POST['token']) ? trim((string) $_POST['token']) : '';

$issued = '';
$header = null;
$payload = null;
$signature = '';
$verifyNote = '';
$error = '';
$granted = false;
$profile = null;

if ($action === 'issue') {
    // 签发一个「普通用户」的 token，作为构造伪造 token 的参照
    $token = jwt_encode(JWT_DEMO_USER, 'HS256', 'secret');
    $issued = $token;
} elseif ($action === 'verify' && $token !== '') {
    [$header, $payload, $signature, $signingInput, $error] = jwt_split($token);

    if ($error === '') {
        // ------------------------------------------------------------------
        // 漏洞点：alg 不是 HS256 时就跳过签名校验
        //
        // 这段代码的写法在真实项目里很常见，它看起来是在「兼容多种算法」，
        // 实际上是把「算法」这个字段的**决定权交给了提交 token 的人**。
        //
        // 正常情况下 alg 是签发方填的；而在这里，攻击者只要把 header 里的
        // alg 改成 none，就能让服务端走进「不校验」那条分支。
        // ------------------------------------------------------------------
        if ($header['alg'] === 'none') {
            $verifyNote = '签名校验：已跳过（token 声明 alg=none，视为无签名）';
            $granted = true;
        } elseif ($header['alg'] === 'HS256') {
            $expected = jwt_hs256_sign($signingInput, 'secret');
            if (hash_equals($expected, $signature)) {
                $verifyNote = '签名校验：通过（HS256）';
                $granted = true;
            } else {
                $verifyNote = '签名校验：不通过（HS256 签名不匹配）';
            }
        } else {
            // 不认识的算法 —— 这里也放行了（同类问题的另一种表现）
            $verifyNote = '签名校验：已跳过（未识别的算法 ' . $header['alg'] . '）';
            $granted = true;
        }

        if ($granted) {
            $profile = [
                '用户' => (string) ($payload['user'] ?? '(未提供)'),
                '角色' => (string) ($payload['role'] ?? '(未提供)'),
            ];
        }
    }
}

$flagVisible = $granted && (($payload['role'] ?? '') === 'admin');
?>
<?php layout_header(
    'JWT · 难度 low',
    '「无法验证它」不等于「它是可信的」—— 这一档演示前者被当成了后者。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    JWT 最常见的误用是把它当成「加密过的、所以内容是可信的」——
    实际上 header 和 payload 只是 <b>base64url 编码，谁都能读、谁都能改</b>。<br>
    全部安全性都压在签名上。签名一旦能被绕过或伪造，token 里的任何字段都可以随便写。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0"><span class="k">if</span> ($header[<span class="s">'alg'</span>] === <span class="s">'none'</span>) {
    <span class="c">// 规范里 alg:none 表示「这个 token 没有签名」</span>
    <span class="c">// —— 那就没有可校验的东西了</span>
    $verifyNote = <span class="s">'已跳过'</span>; $granted = <span class="f">true</span>;   <span class="c">// ← 问题在这一行</span>
} <span class="k">elseif</span> ($header[<span class="s">'alg'</span>] === <span class="s">'HS256'</span>) {
    <span class="c">// 正常校验签名</span>
}</pre>
  <p style="margin:10px 0 0;font-size:14px;color:var(--muted)">
    <code>alg</code> 本来是<b>签发方</b>决定的事情，但它是 token 里的一个字段 ——
    也就是说，它由<b>提交 token 的人</b>控制。
  </p>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    现在你手上只有普通用户 <code>alice</code> 的 token。
    让服务端认为你是 <code>role=admin</code>，拿到通关凭证。
  </p>
  <p class="hint" style="margin:8px 0 0">
    凭证只在角色确实是 <code>admin</code> 时才显示 —— 所以它本身不能当作判据，
    得先把 <code>role</code> 改对。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">第一步：拿一个 token 看看它长什么样</h3>
  <form method="post" action="low.php" style="margin-bottom:10px">
    <input type="hidden" name="action" value="issue">
    <button type="submit">签发一个 alice（role=user）的 token</button>
  </form>

  <?php if ($issued !== ''): ?>
    <?php render_code_board('刚签发的 token', $issued); ?>
    <p class="hint" style="margin:10px 0 0">
      把它复制出来，用「.<code>.</code>」拆成三段，分别做 base64url 解码 ——
      header 和 payload 都是明文 JSON，看得一清二楚。
      <br>
      <span style="opacity:.75">
        命令行里可以这样做（base64url 需要把 <code>-</code> <code>_</code> 换回 <code>+</code> <code>/</code>、再补上 <code>=</code>）：
        <code>echo '段内容' | tr '_-' '/+' | base64 -d</code>
      </span>
    </p>
  <?php endif; ?>
</div>

<div class="card">
  <h3 style="margin-top:0">第二步：提交一个 token</h3>
  <form method="post" action="low.php">
    <input type="hidden" name="action" value="verify">
    <div class="row">
      <textarea name="token" rows="5" style="flex:1;font-family:var(--mono);font-size:12px"
                placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9.xxx"
      ><?= htmlspecialchars($token) ?></textarea>
    </div>
    <div class="row">
      <button type="submit">校验并查看资料</button>
    </div>
  </form>
</div>

<?php if ($action === 'verify' && $token !== ''): ?>
  <?php if ($error !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
    </div>
  <?php else: ?>
    <div class="card">
      <h3 style="margin-top:0">服务端看到的 token</h3>
      <?php render_jwt_breakdown($header, $payload, $signature, [
          '签名校验结果' => $verifyNote,
          '是否放行' => $granted ? '✓ 放行' : '✗ 拒绝',
      ]); ?>
    </div>

    <div class="card" style="<?= $flagVisible ? 'border-color:#fecaca;background:var(--danger-soft)' : '' ?>">
      <h3 style="margin-top:0">个人资料</h3>
      <?php if (!$granted): ?>
        <p style="margin:0;color:var(--danger);font-weight:500">token 未通过校验，拒绝访问。</p>
      <?php else: ?>
        <div class="kv"><b>用户</b><span class="mono"><?= htmlspecialchars($profile['用户']) ?></span></div>
        <div class="kv"><b>角色</b><span class="mono"><?= htmlspecialchars($profile['角色']) ?></span></div>

        <?php if ($flagVisible): ?>
          <p style="margin:14px 0 0;color:var(--danger);font-weight:500">
            ★ 服务端认为你是管理员，通关凭证：
          </p>
          <pre style="margin:6px 0 0"><?= htmlspecialchars(JWT_FLAG) ?></pre>
        <?php else: ?>
          <p class="hint" style="margin:14px 0 0">
            通关凭证只对 <code>role=admin</code> 显示。你现在是 <code><?= htmlspecialchars($profile['角色']) ?></code>。
          </p>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>token 的三段分别是什么？哪一段是**签名**？</li>
    <li>签名是「对什么内容」算出来的？（把第二段改一个字，签名还对不对？）</li>
    <li>如果我把 header 里的 <code>alg</code> 改成别的东西，服务端会走哪条分支？</li>
    <li>改完 header 和 payload 之后，第三段（签名）还需要是正确的吗？</li>
    <li>JWT 规范里 <code>alg: none</code> 是什么意思？它本来就是给什么场景用的？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/jwt.md</code>。</p>
</div>

<?php layout_footer(); ?>
