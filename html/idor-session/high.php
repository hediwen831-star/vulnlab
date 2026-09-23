<?php
/**
 * 会话凭据 · high 档 —— 凭据由服务端生成，客户端造不出来
 *
 * 身份来源：`Cookie: sid=<随机会话令牌>`，服务端查自己持有的映射表还原 uid
 * 归属校验：**有**
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 修复点：把「客户端能造出来的值」换成「服务端随机的值」
 * ══════════════════════════════════════════════════════════════════
 *
 * 三档的差别可以压缩成一行对比：
 *
 *     low    ：$uid = (int) $_COOKIE['sid'];        // 明文，改数字即可
 *     medium ：$uid = (int) base64_decode($sid);    // 编码，解开改掉再编回去
 *     high   ：$uid = $tokenStore->resolve($sid);   // 查表，造不出别的条目
 *
 * 前两档的 `sid` 都是**从 uid 算出来的** —— 只要知道算法，就能造出任意一个。
 *
 * high 档的 `sid` **不是算出来的，是发出来的**：服务端生成一个随机串、
 * 记住它对应哪个用户，然后把随机串给客户端。客户端手里只有自己那一个。
 *
 * ── 这条界线怎么划 ──
 *
 *     凭据 = 客户端**持有**的东西，而不是客户端**知道怎么算**的东西。
 *
 * 密码、会话 ID、签名后的 token 属于前者。
 * 明文 uid、base64(uid)、uid+时间戳的哈希属于后者 ——
 * 只要算法是公开的（而它必然是公开的，因为客户端要能生成请求），
 * 客户端就能造出任何人的凭据。
 *
 * ── PHP 自己的会话就是这么做的 ──
 *
 * `session_start()` 生成的 `PHPSESSID` 是一个随机串，服务端把
 * 「随机串 → 会话数据」存在文件或 Redis 里 —— 就是本档这个结构。
 * 它安全的唯一原因是：**随机串猜不出来**（足够长的随机值），
 * 而不是因为「客户端看不见」。
 *
 * 注意最后这半句：客户端**看得见**自己的会话 ID（就在 Cookie 里），
 * 这没关系。凭据本来就是给持有者用的。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/store.php';

// ----------------------------------------------------------------------
// 身份解析：查服务端持有的映射表
//
// 这里没有「解码」也没有「还原」—— 因为令牌里根本没有编码任何信息。
// 它只是一个索引，指向服务端自己记录的那一行。
// ----------------------------------------------------------------------
$rawSid = isset($_COOKIE['sid']) ? trim((string) $_COOKIE['sid']) : null;
$currentUid = null;

if ($rawSid !== null && $rawSid !== '' && isset(SESSION_TOKENS[$rawSid])) {
    $currentUid = SESSION_TOKENS[$rawSid];
}

/** 演示用的自有令牌 —— 相当于「你这个浏览器当前登录的那个会话」 */
$ownToken = 'a1b2c3d4e5f6';   // alice 的令牌，仅用于让访问者有个合法身份可用

$orderId = isset($_GET['order_id']) ? trim((string) $_GET['order_id']) : '';
$submitted = ($orderId !== '');

$order = null;
$error = '';
$isOwner = false;
$sqlShown = '';

if ($submitted) {
    // 归属校验 + 服务端解析出的身份 —— 两者都到位
    //
    // ⚠️ 和 medium 档同样的注意点：凭据无效时必须直接拒绝。
    //    session_find_order($id, null) 表示「不按归属过滤」，
    //    若把「未登录」也传成 null，未登录的人反而能读到所有订单。
    $effectiveUid = $currentUid;

    if ($effectiveUid === null) {
        $error = '凭据不在服务端的会话表中 —— 未登录，拒绝查询。';
    } else {
        $sqlShown = 'SELECT * FROM orders WHERE id = ' . $orderId
            . ' AND user_id = ' . $effectiveUid;

        $order = session_find_order($orderId, $effectiveUid);

        if ($order === null) {
            $error = '订单不存在，或不属于当前用户。';
        } else {
            $isOwner = ((int) $order['uid'] === $effectiveUid);
        }
    }
}

$myOrders = [];
if ($currentUid !== null) {
    foreach (SESSION_ORDERS as $o) {
        if ((int) $o['uid'] === $currentUid) {
            $myOrders[] = $o;
        }
    }
}

?>
<?php layout_header(
    '会话凭据 · 难度 high',
    '凭据由服务端随机发放并自己记住 —— 客户端手里只有属于自己那一个。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的做法</h3>
  <pre style="margin:10px 0 0"><span class="c">// 服务端生成随机令牌，记住它对应哪个用户</span>
$token = <span class="v">bin2hex</span>(<span class="v">random_bytes</span>(6));
$tokenStore[$token] = $uid;

<span class="c">// 下次请求：查表还原身份（不是解码，是查表）</span>
$uid = $tokenStore[$_COOKIE[<span class="s">'sid'</span>]] ?? <span class="k">null</span>;
<span class="c">//      ↑ 客户端没有别的条目，也就造不出别的身份</span>

<span class="c">// 归属校验照旧</span>
SELECT * FROM orders WHERE id = ? AND <span class="v">user_id</span> = ?</pre>
  <p class="hint" style="margin:12px 0 0">
    关键不在「令牌看不看得懂」，而在于**客户端只能拿到发给自己的那一个**。
  </p>
</div>

<div class="card" style="border-color:#bbf7d0;background:#f0fdf4">
  <h3 style="margin-top:0">试着伪造一下</h3>
  <p style="margin:0 0 10px;font-size:14px">
    你可以用自己的令牌访问，读自己的订单：
  </p>
  <pre style="margin:0 0 12px;font-size:13px">curl -b "sid=<?= htmlspecialchars($ownToken) ?>" \
     "http://127.0.0.1:8080/idor-session/high.php?order_id=1001"</pre>
  <p style="margin:0;font-size:14px">
    然后试着读 <code>1003</code>（bob 的订单）—— 应该被挡下。<br>
    也可以试着把 <code>sid</code> 改成别的值、或者手工构造一个——
    服务端的表里没有这个条目，只会被当作未登录。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">服务端认为你是谁</h3>
  <div class="kv">
    <b>请求里的凭据</b>
    <span class="mono"><?= $rawSid === null ? '(未携带 Cookie: sid)' : htmlspecialchars($rawSid) ?></span>
  </div>
  <div class="kv">
    <b>查表结果</b>
    <span class="mono">
      <?php if ($currentUid === null): ?>
        表中无此条目 → 视为未登录
      <?php else: ?>
        命中 → uid=<?= htmlspecialchars((string) $currentUid) ?>
        （<?= htmlspecialchars(session_username($currentUid)) ?>）
      <?php endif; ?>
    </span>
  </div>
  <p class="hint" style="margin:12px 0 0">
    令牌里没有编码任何信息，服务端也无法「还原」出什么 —— 它只能查表。
    这正是它不可伪造的原因。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">我的订单</h3>
  <?php if ($currentUid === null): ?>
    <p style="margin:0;color:var(--muted);font-size:14px">
      未携带有效的 <code>Cookie: sid</code>，无法确定身份。
      演示令牌：<code>sid=<?= htmlspecialchars($ownToken) ?></code>
    </p>
  <?php else: ?>
    <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
      （服务端按当前用户过滤后的结果）
    </p>
    <div class="links">
      <?php foreach ($myOrders as $o): ?>
        <a href="?order_id=<?= urlencode((string) $o['id']) ?>"><?= htmlspecialchars($o['id'] . '（' . $o['item'] . '）') ?></a>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>
</div>

<div class="card">
  <h3 style="margin-top:0">查询订单详情</h3>
  <form method="get" action="high.php">
    <div class="row">
      <label style="min-width:90px">订单号</label>
      <input type="text" name="order_id" style="flex:1;font-family:var(--mono)"
             value="<?= htmlspecialchars($orderId) ?>" placeholder="1001">
    </div>
    <div class="row">
      <button type="submit">查询</button>
    </div>
  </form>
  <?php if ($sqlShown !== ''): ?>
    <?php render_code_board('服务端执行的查询', $sqlShown); ?>
  <?php endif; ?>
</div>

<?php if ($submitted): ?>
  <?php if ($error !== ''): ?>
    <div class="card"><p style="margin:0;color:var(--danger)"><?= htmlspecialchars($error) ?></p></div>
  <?php else: ?>
    <?php render_session_order($order, $isOwner); ?>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">这一档要理解什么</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>为什么这里「改 Cookie」不再有效？和 medium 档的差别到底在哪一行？</li>
    <li>如果会话令牌只有 4 位十六进制（约 6.5 万个组合），会变成什么问题？</li>
    <li>令牌泄露（XSS、日志、Referer）之后，这一档的防护还成立吗？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/idor-session.md</code>。</p>
</div>

<?php layout_footer(); ?>
