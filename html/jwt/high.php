<?php
/**
 * JWT · high 档 —— 修复对照
 *
 * 修复方式：**算法白名单 + 高熵密钥 + 定长比较 + 必需声明校验。**
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码的修复版，请勿删改其中的防护逻辑。
 *
 * ══════════════════════════════════════════════════════════════════
 * 前两档的失败模式
 * ══════════════════════════════════════════════════════════════════
 *
 *   low    ：`alg:none` 被当成「没有签名可校验 → 放行」
 *            → 攻击者改一个字段就能进
 *
 *   medium ：算法判断写对了，签名也真的在比对 —— 但密钥是 `secret`
 *            → 攻击者猜出密钥后，自己算一个「合法」签名
 *
 * 这两档暴露了两个**完全不同**的问题：
 *
 *   ① 逻辑问题：把「无法验证」当成了「可信」（low）
 *   ② 配置问题：密钥强度不足（medium）
 *
 * 所以修复也必须分别针对这两件事，缺一不可。
 * 只修 ① 会停在 medium 的水平（校验写对，密钥照样能被猜）；
 * 只修 ② 会停在 low 的水平（密钥再强，alg 能被改成 none 也没用）。
 *
 * ══════════════════════════════════════════════════════════════════
 * 四层防护
 * ══════════════════════════════════════════════════════════════════
 *
 *   ① 算法白名单 —— 显式列举接受的算法，其余一律拒绝
 *
 *      关键在措辞：「只接受 HS256」和「除了 none 之外都接受」是两回事。
 *      前者是白名单，后者是黑名单 —— 而 JWT 规范里的算法不止一个，
 *      黑名单永远列不全（RS256 / ES256 / PS256 … 以及各种大小写变体）。
 *
 *      **判断的依据应该是「我支持什么」，而不是「有什么是危险的」。**
 *
 *   ② 高熵密钥 —— 从环境变量读取，默认值也是随机生成的 32 字节
 *
 *      密钥不能是「人想出来的词」。32 字节随机值的搜索空间是 2^256，
 *      爆破在物理上不可行；而 `secret` 只要试一次。
 *
 *      ⚠️ 注意下面读环境变量的写法 —— 生产环境必须走环境变量 / KMS，
 *         把密钥写在源码里，等于任何能看到源码的人都能伪造 token。
 *         这里的默认值只是为了靶场可以开箱即用。
 *
 *   ③ 定长比较 —— `hash_equals()` 而不是 `===`
 *
 *      `===` 在第一个不同的字节处就返回，比较时间会随「猜对了多少字节」
 *      而变化。理论上可以据此逐字节爆破签名。
 *      这一层在实际攻击中较难利用（网络抖动会淹没时间差），
 *      但成本极低，没有理由不写。
 *
 *   ④ 必需声明校验 —— `exp` 必须存在且未过期
 *
 *      签名有效 ≠ 这个 token 现在还能用。
 *      少了这一层，一个泄露的旧 token 会永远有效。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/jwt.php';

/**
 * 写死在源码里的密钥 —— 生产环境不该这样。
 *
 * 正确做法是从环境变量 / 密钥管理服务读取：
 *     $secret = getenv('JWT_SECRET') ?: throw new RuntimeException('未配置 JWT_SECRET');
 *
 * 靶场里给了一个高熵的默认值，是为了让场景开箱即用；
 * 但上面那行才是真实项目该有的样子 —— 而且它必须**在缺失时拒绝启动**，
 * 而不是退回到一个默认的弱密钥（那才是最危险的做法）。
 */
const HIGH_SECRET_DEFAULT = 'JAhC6BOdck39cPzL0QSADZ1ZBtYQvZ7Nufq1Z9yxp7w=';

/** token 有效期（秒） */
const HIGH_TOKEN_TTL = 3600;

$action = isset($_POST['action']) ? (string) $_POST['action'] : '';
$token = isset($_POST['token']) ? trim((string) $_POST['token']) : '';

$issued = '';
$header = null;
$payload = null;
$signature = '';
$audit = [];
$error = '';
$granted = false;
$profile = null;

$secret = (string) (getenv('JWT_SECRET') ?: HIGH_SECRET_DEFAULT);

if ($action === 'issue') {
    $token = jwt_encode(
        JWT_DEMO_USER + ['iat' => time(), 'exp' => time() + HIGH_TOKEN_TTL],
        'HS256',
        $secret
    );
    $issued = $token;
} elseif ($action === 'verify' && $token !== '') {
    [$header, $payload, $signature, $signingInput, $error] = jwt_split($token);

    if ($error === '') {
        // --------------------------------------------------------------
        // 层 ①：算法白名单
        //
        // 白名单的写法很直接：**只列举我认的**。
        // 不在这里的一律拒绝 —— 包括 none、包括大写变体、包括
        // 任何这个实现没打算支持的东西。
        // --------------------------------------------------------------
        $allowedAlgs = ['HS256'];
        if (!in_array($header['alg'], $allowedAlgs, true)) {
            $audit[] = ['① 算法白名单', $header['alg'], '✗ 不在白名单内（仅 ' . implode('/', $allowedAlgs) . '）'];
            $error = 'token 被拒绝：不支持的算法。';
        } else {
            $audit[] = ['① 算法白名单', $header['alg'], '✓ 在白名单内'];

            // ----------------------------------------------------------
            // 层 ③：定长比较
            // ----------------------------------------------------------
            $expected = jwt_hs256_sign($signingInput, $secret);
            if (!hash_equals($expected, $signature)) {
                $audit[] = ['③ 签名比较', 'hash_equals 结果：不匹配', '✗ 签名无效'];
                $error = 'token 被拒绝：签名不匹配。';
            } else {
                $audit[] = ['③ 签名比较', 'hash_equals 结果：匹配', '✓ 签名有效'];
            }
        }

        if ($error === '') {
            // ----------------------------------------------------------
            // 层 ④：必需声明校验
            //
            // 签名有效只说明「这个 token 是我们签的」，
            // 不代表「它现在还能用」。少了这一层，泄露的旧 token 永久有效。
            // ----------------------------------------------------------
            $exp = $payload['exp'] ?? null;
            if (!is_int($exp)) {
                $audit[] = ['④ 有效期声明', '缺少 exp', '✗ 拒绝（无法判断是否过期）'];
                $error = 'token 被拒绝：缺少有效期声明。';
            } elseif ($exp < time()) {
                $audit[] = ['④ 有效期声明', 'exp = ' . $exp, '✗ 已过期'];
                $error = 'token 被拒绝：已过期。';
            } else {
                $audit[] = ['④ 有效期声明', '剩余 ' . ($exp - time()) . ' 秒', '✓ 未过期'];
            }
        }

        if ($error === '') {
            $granted = true;
            $profile = [
                '用户' => (string) ($payload['user'] ?? '(未提供)'),
                '角色' => (string) ($payload['role'] ?? '(未提供)'),
            ];
        }
    }
}

$flagVisible = $granted && (($payload['role'] ?? '') === 'admin');

/** 攻击载荷对照 */
$attacks = [
    ['alg:none（low 档手法）', '把 header 的 alg 改成 none、把签名段留空'],
    ['弱密钥签名（medium 档手法）', '用 secret 作为密钥重新计算签名'],
];
?>
<?php layout_header(
    'JWT · 难度 high（已修复）',
    '逻辑问题和配置问题要分别修 —— 只修一边，另一边照样能进。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护（四层）</h3>
  <pre style="margin:10px 0 0;background:#064e3b"><span class="c">// ① 算法白名单 —— 只列举我支持的，其余一律拒绝</span>
<span class="k">if</span> (!in_array($header[<span class="s">'alg'</span>], [<span class="s">'HS256'</span>], <span class="f">true</span>)) { <span class="c">/* 拒绝 */</span> }

<span class="c">// ② 高熵密钥 —— 从环境变量读，默认值也是 32 字节随机</span>
$secret = <span class="v">getenv</span>(<span class="s">'JWT_SECRET'</span>) ?: HIGH_SECRET_DEFAULT;

<span class="c">// ③ 定长比较 —— 不用 ===，避免比较时间泄露信息</span>
<span class="k">if</span> (!<span class="v">hash_equals</span>($expected, $signature)) { <span class="c">/* 拒绝 */</span> }

<span class="c">// ④ 必需声明 —— 签名有效 ≠ 现在还能用</span>
<span class="k">if</span> (!is_int($payload[<span class="s">'exp'</span>] ?? <span class="f">null</span>) || $payload[<span class="s">'exp'</span>] &lt; <span class="v">time</span>()) { <span class="c">/* 拒绝 */</span> }</pre>
  <p style="margin:10px 0 0;font-size:14px;color:#065f46">
    <b>① 和 ② 必须同时存在。</b>
    只修 ① 会停在 medium 的水平（校验写对，密钥照样能被猜）；
    只修 ② 会停在 low 的水平（密钥再强，<code>alg</code> 能被改成 none 也没用）。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">第一步：拿一个正常 token</h3>
  <form method="post" action="high.php" style="margin-bottom:10px">
    <input type="hidden" name="action" value="issue">
    <button type="submit">签发一个 alice（role=user）的 token</button>
  </form>
  <?php if ($issued !== ''): ?>
    <?php render_code_board('刚签发的 token（含 iat / exp）', $issued); ?>
  <?php endif; ?>
</div>

<div class="card">
  <h3 style="margin-top:0">第二步：提交一个 token</h3>
  <form method="post" action="high.php">
    <input type="hidden" name="action" value="verify">
    <div class="row">
      <textarea name="token" rows="5" style="flex:1;font-family:var(--mono);font-size:12px"
                placeholder="把 low / medium 档成功的 token 粘进来试试"
      ><?= htmlspecialchars($token) ?></textarea>
    </div>
    <div class="row">
      <button type="submit">校验并查看资料</button>
    </div>
  </form>
  <p class="hint">把前两档成功的 token 原样粘进来 —— 四层各自都会让它失败。</p>
</div>

<?php if ($action === 'verify' && $token !== ''): ?>
  <?php if ($error !== '' && $header === null): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
    </div>
  <?php else: ?>
    <div class="card tight" style="margin-bottom:14px">
      <div style="font-size:13px;color:var(--muted);margin-bottom:10px">校验过程（逐层审计）</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th style="width:22%">层</th><th style="width:46%">观察到的值</th><th>结果</th></tr></thead>
          <tbody>
            <?php foreach ($audit as [$layer, $value, $result]): ?>
              <tr>
                <td><?= htmlspecialchars($layer) ?></td>
                <td class="mono" style="word-break:break-all"><?= htmlspecialchars($value) ?></td>
                <td style="color:<?= strpos($result, '✗') === 0 ? 'var(--danger)' : 'var(--ok)' ?>;font-weight:500">
                  <?= htmlspecialchars($result) ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3 style="margin-top:0">服务端看到的 token</h3>
      <?php render_jwt_breakdown($header, $payload, $signature, [
          '校验结果' => $error !== '' ? '✗ ' . $error : '✓ 通过',
      ]); ?>
    </div>

    <div class="card">
      <h3 style="margin-top:0">个人资料</h3>
      <?php if (!$granted): ?>
        <p style="margin:0;color:var(--danger);font-weight:500">token 未通过校验，拒绝访问。</p>
      <?php else: ?>
        <div class="kv"><b>用户</b><span class="mono"><?= htmlspecialchars($profile['用户']) ?></span></div>
        <div class="kv"><b>角色</b><span class="mono"><?= htmlspecialchars($profile['角色']) ?></span></div>
        <?php if ($flagVisible): ?>
          <p style="margin:14px 0 0;color:var(--danger);font-weight:500">
            ★ 注意：这个 token 通过了全部校验，而且角色是 admin。
          </p>
          <p style="margin:6px 0 0;font-size:14px;color:#b91c1c">
            校验逻辑本身没有失败 —— 四层都放行了。这意味着这个 token
            <b>确实是由持有密钥的一方签发的</b>：要么本档的密钥已经泄露，
            要么你能拿到它（源码 / 环境变量 / 配置）。
            <br>
            换句话说：<b>JWT 的防护上限就是密钥的保密程度。</b>
          </p>
        <?php else: ?>
          <p style="margin:14px 0 0;color:var(--ok);font-weight:500">
            ✓ 正常 token 照常可用 —— 修复没有牺牲功能
          </p>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">攻击载荷对照（都被挡住）</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:32%">载荷</th><th>被哪一层挡住</th></tr></thead>
      <tbody>
        <?php foreach ($attacks as [$label, $how]): ?>
          <tr>
            <td style="font-size:13px"><?= htmlspecialchars($label) ?></td>
            <td style="font-size:13px;color:var(--muted)"><?= htmlspecialchars($how) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <p class="hint">
    ① 挡住 alg:none；② 让「猜密钥」不可行；③④ 是额外的纵深防御。
    <b>① 和 ② 是必选项，缺一个都会退回上一档的水平。</b>
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">修复要点总结</h3>
  <ol style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>算法用白名单</b> —— 写「只接受 HS256」，而不是「除了 none 都接受」。
      判据是「我支持什么」，不是「什么是危险的」
    </li>
    <li>
      <b>密钥必须是随机生成的足够长的字节串</b> ——
      不要用「想出来的词」。人想出来的东西，字典里都有
    </li>
    <li>
      <b>密钥不要写在源码里</b> —— 走环境变量 / 密钥管理服务。
      并且<b>缺失时应该拒绝启动</b>，而不是退回到一个默认值
    </li>
    <li>
      <b>用 <code>hash_equals()</code> 而不是 <code>===</code></b> ——
      避免比较时间泄露信息，成本极低
    </li>
    <li>
      <b>校验必需声明（<code>exp</code> / <code>iat</code> / <code>aud</code> / <code>iss</code>）</b> ——
      签名有效 ≠ 这个 token 现在还能用
    </li>
    <li>
      <b>优先用成熟的库</b> —— 本场景手写实现是为了把缺陷摆在明面上。
      真实项目里，成熟库已经替你处理了算法白名单、时序比较这些细节
    </li>
  </ol>
  <p class="hint">
    最容易踩的一条：<b>「我用了 JWT，所以我的认证是安全的」。</b><br>
    JWT 只是一个格式。格式本身不提供任何安全性 ——
    安全性来自「算法判断是否正确」和「密钥是否足够强」这两件事，
    而这两件事都得由写代码的人负责。
  </p>
</div>

<?php layout_footer(); ?>
