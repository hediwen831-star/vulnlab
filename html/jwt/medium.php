<?php
/**
 * JWT · medium 档 —— 签名校验正常，但密钥是弱口令
 *
 * 防护方式：**只接受 HS256，并且真的校验签名。**
 * 也就是说，low 档那个 `alg:none` 的口子被堵上了。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 这一档换了攻击面：从「绕过校验」变成「伪造校验结果」
 * ══════════════════════════════════════════════════════════════════
 *
 * low 档的问题是**校验逻辑有分支可以绕过**。这一档把逻辑写对了：
 *
 *     · 算法只认 HS256（`alg:none` 会被拒）
 *     · 签名不匹配就拒绝
 *     · 比较用 hash_equals（防时序侧信道）
 *
 * 到这里，「绕过校验」这条路走不通了。于是攻击换了目标：
 * **既然校验绕不过去，那就让我的 token 通过校验。**
 *
 * 而要伪造一个能通过校验的 token，只需要知道密钥 ——
 * 因为 HS256 的签名是 `HMAC-SHA256(header.payload, 密钥)`，
 * 密钥一旦已知，任何人都能算出合法签名。
 *
 * ── 所以这一档真正的问题不是代码，是那个密钥的值 ──
 *
 *     `secret`
 *
 * 这串东西出现在几乎每一份 JWT 教程、示例代码、脚手架配置里。
 * 攻击者根本不需要「猜」—— 直接照着常见示例的密钥列表试就行了。
 * 本目录下的 `wordlist.txt` 就是那种列表的一个缩减版。
 *
 * ── 值得注意的一点 ──
 *
 * 这一档的代码比 low 档「更正确」，但**安全性并没有更高**。
 * 因为它把一个致命的问题留在了配置里：
 * **密钥是人的记忆产物，而人的记忆倾向于选择好记的东西。**
 *
 * 密码学上的密钥不应该由人来「想」出来 —— 应该是随机生成的、
 * 长度足够的字节串，人根本记不住、也不该记住。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/jwt.php';

/** 本档的密钥 —— 故意用弱口令 */
const MEDIUM_SECRET = 'secret';

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
    $token = jwt_encode(JWT_DEMO_USER, 'HS256', MEDIUM_SECRET);
    $issued = $token;
} elseif ($action === 'verify' && $token !== '') {
    [$header, $payload, $signature, $signingInput, $error] = jwt_split($token);

    if ($error === '') {
        // ------------------------------------------------------------------
        // 这一档把算法判断写对了：不是白名单里的，一律拒绝
        //
        // 注意这里用的是「显式判断 + 拒绝」，而不是 low 档那种
        // 「认识的处理、不认识的放过」。这个区别很关键：
        // 前者是白名单，后者实质上是「把决定权交给输入」。
        // ------------------------------------------------------------------
        if ($header['alg'] !== 'HS256') {
            $verifyNote = '签名校验：拒绝（只接受 HS256，收到 ' . $header['alg'] . '）';
        } else {
            $expected = jwt_hs256_sign($signingInput, MEDIUM_SECRET);

            // hash_equals 做定长比较，避免通过响应时间逐字节猜签名
            if (hash_equals($expected, $signature)) {
                $verifyNote = '签名校验：通过（HS256）';
                $granted = true;
            } else {
                $verifyNote = '签名校验：不通过（HS256 签名不匹配）';
            }
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
    'JWT · 难度 medium',
    '校验逻辑写对了 —— 但密钥是「secret」。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0"><span class="c">// 算法白名单</span>
<span class="k">if</span> ($header[<span class="s">'alg'</span>] !== <span class="s">'HS256'</span>) { <span class="c">/* 拒绝 */</span> }

<span class="c">// 正常校验签名（比较用 hash_equals，防时序侧信道）</span>
<span class="k">if</span> (<span class="v">hash_equals</span>($expected, $signature)) { <span class="c">/* 通过 */</span> }

<span class="c">// 密钥</span>
<span class="k">const</span> MEDIUM_SECRET = <span class="s">'secret'</span>;   <span class="c">// ← 问题在这里</span></pre>
  <p style="margin:10px 0 0;font-size:14px;color:var(--muted)">
    代码层面的问题都修掉了。<code>alg:none</code> 会被拒、签名不匹配会被拒。
    剩下的唯一问题：<b>密钥的值是个人人都知道的词。</b>
  </p>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    同样要拿到 <code>role=admin</code> 的凭证。
    但这次你不能靠改 header 蒙混过关 —— 得先弄清楚签名是怎么算的，
    再想办法知道那个密钥是什么。
  </p>
  <p class="hint" style="margin:12px 0 0">
    本目录下有一份小小的弱密钥列表：<code>wordlist.txt</code>。
    真实攻击里用的是几十万行的大字典，这里只保留最常见的若干条，
    让爆破这件事在本地几秒内就能跑完。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">第一步：拿一个 token 看看它长什么样</h3>
  <form method="post" action="medium.php" style="margin-bottom:10px">
    <input type="hidden" name="action" value="issue">
    <button type="submit">签发一个 alice（role=user）的 token</button>
  </form>
  <?php if ($issued !== ''): ?>
    <?php render_code_board('刚签发的 token', $issued); ?>
  <?php endif; ?>
</div>

<div class="card">
  <h3 style="margin-top:0">第二步：提交一个 token</h3>
  <form method="post" action="medium.php">
    <input type="hidden" name="action" value="verify">
    <div class="row">
      <textarea name="token" rows="5" style="flex:1;font-family:var(--mono);font-size:12px"
                placeholder="把伪造好的 token 粘进来"
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
            ★ 你伪造出了合法的签名，通关凭证：
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
  <h3 style="margin-top:0">核心绕过点：从「绕过校验」转向「伪造校验结果」</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:22%">档位</th><th style="width:30%">校验能不能绕过</th><th>攻击者转而做什么</th></tr></thead>
      <tbody>
        <tr>
          <td>low</td>
          <td>能（<code>alg:none</code>）</td>
          <td>直接把 <code>alg</code> 改成 none，不用管签名</td>
        </tr>
        <tr>
          <td>medium</td>
          <td><b>不能</b></td>
          <td>
            <b>猜出密钥</b>，然后自己算出一个「合法」的签名 ——<br>
            校验逻辑毫发无损，token 却完全是自己写的
          </td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="hint">
    这是本场景最值得记住的一点：<br>
    <b>把校验写对，和让校验有意义，是两件不同的事。</b><br>
    一个用 <code>secret</code> 当密钥的 HS256 实现，
    代码可以完全正确 —— 但它挡不住任何一个会写脚本的人。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>HMAC-SHA256 的输入是什么？签名段的字节是怎么来的？</li>
    <li>要自己算一个合法签名，你手上还差什么？</li>
    <li>那个东西能不能猜出来？想想「示例代码里最常见的密钥是什么」。</li>
    <li>试试把 <code>wordlist.txt</code> 里的词逐个拿去算签名，和真实 token 的第三段比对 —— 一致就说明猜对了。</li>
    <li>猜对之后，把 payload 里的 <code>role</code> 改成 <code>admin</code>，用自己的密钥重新签名。</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/jwt.md</code>。</p>
</div>

<?php layout_footer(); ?>
