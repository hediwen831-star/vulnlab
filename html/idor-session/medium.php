<?php
/**
 * 会话凭据 · medium 档 —— 编码被当成了签名
 *
 * 身份来源：`Cookie: sid=<base64(uid)>`
 * 归属校验：**有**（这一档的 SQL 是正确的）
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 这一档「看起来已经做了安全处理」
 * ══════════════════════════════════════════════════════════════════
 *
 * 和 low 档比，这里有两处改动，都朝着「更安全」的方向：
 *
 *     ① Cookie 里不再是明文 uid，而是一串看不懂的字符
 *     ② 归属校验确实加上了（WHERE id = ? AND user_id = ?）
 *
 * 评审的时候这两点很容易让人放心：值不可读、SQL 也对了。
 *
 * 但把它解开看一眼：
 *
 *     base64_decode("Mw==")  →  "3"
 *
 * 它是 uid 换了个写法而已。
 *
 * ── 编码和签名的区别 ──
 *
 *     编码（encoding）：把数据换成另一种表示。**任何人都会做，不需要密钥。**
 *                       base64、hex、URL 编码、rot13 都属于这一类。
 *
 *     签名（signing） ：用服务端持有的密钥算出一段校验值。
 *                       客户端**没有密钥就造不出来**。
 *
 *     加密（encryption）：用密钥把内容变成不可读。客户端没有密钥读不出来。
 *
 * 三者解决的是不同问题。「不可读」不等于「不可伪造」——
 * base64 后的内容照样可以解开、改掉、再编回去。
 *
 * ── 判别方法 ──
 *
 * 问一句就够了：
 *
 *     **这个值里的信息，客户端能不能自己造出来？**
 *
 * 能造出来的（明文、base64、自增 ID、时间戳拼的串），就不是凭据。
 * 造不出来的（服务端随机的、带密钥签名的），才是。
 *
 * 真实的例子：把 `user_id=123` 换成 `user_id=MTIz` 就以为安全了 ——
 * 类似的写法在真实项目里并不少见，而且往往还伴随着注释
 * 「已做加密处理」。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/store.php';

// ----------------------------------------------------------------------
// 身份解析：base64 解码后就是 uid
//
// base64_decode 的第二个参数 true 表示「严格模式」——
// 它只保证输入是合法的 base64，**不代表内容经过了任何校验**。
// 这个参数名容易让人产生「严格 = 安全」的错觉。
// ----------------------------------------------------------------------
$rawSid = isset($_COOKIE['sid']) ? trim((string) $_COOKIE['sid']) : null;
$decodedText = null;
$currentUid = null;

if ($rawSid !== null && $rawSid !== '') {
    $decoded = base64_decode($rawSid, true);
    if ($decoded !== false) {
        $decodedText = $decoded;
        $candidate = (int) $decoded;
        if (isset(SESSION_USERS[$candidate])) {
            $currentUid = $candidate;
        }
    }
}

$orderId = isset($_GET['order_id']) ? trim((string) $_GET['order_id']) : '';
$submitted = ($orderId !== '');

$order = null;
$error = '';
$isOwner = false;
$sqlShown = '';

if ($submitted) {
    // ------------------------------------------------------------------
    // 归属校验在这里 —— 这行代码本身是完全正确的
    //
    // 它唯一的依赖是 $currentUid 可信。而那个值来自客户端。
    //
    // ⚠️ 凭据无效时必须**直接拒绝**，不能把 null 传下去 ——
    //    session_find_order 的第二个参数为 null 时表示「不按归属过滤」，
    //    那是 low 档才需要的语义。两种含义混用，会让「未登录」退化成
    //    「谁都能看」，把这一档的防护整个绕过去。
    // ------------------------------------------------------------------
    $effectiveUid = $currentUid;

    if ($effectiveUid === null) {
        $error = '凭据无效或已失效 —— 未登录，拒绝查询。';
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
    '会话凭据 · 难度 medium',
    '归属校验是对的；问题在于它依赖的那个身份，是客户端自己编的。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的两处改动</h3>
  <pre style="margin:10px 0 0"><span class="c">// ① Cookie 里不再是明文，看起来「加密」了</span>
$sid = $_COOKIE[<span class="s">'sid'</span>];
$uid = (<span class="k">int</span>) <span class="v">base64_decode</span>($sid, <span class="k">true</span>);
<span class="c">//    base64_decode("Mw==") → "3"     只是换了个写法</span>

<span class="c">// ② 归属校验 —— 这行是对的</span>
SELECT * FROM orders WHERE id = ? AND <span class="v">user_id</span> = ?</pre>
  <p class="hint" style="margin:12px 0 0">
    编码（base64 / hex / URL 编码）不需要密钥，任何人都能解开再编回去。
    它和签名解决的不是同一个问题。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">服务端认为你是谁</h3>
  <div class="kv">
    <b>请求里的凭据</b>
    <span class="mono"><?= $rawSid === null ? '(未携带 Cookie: sid)' : htmlspecialchars($rawSid) ?></span>
  </div>
  <div class="kv">
    <b>解码后的明文</b>
    <span class="mono"><?= $decodedText === null ? '(无法解码)' : htmlspecialchars($decodedText) ?></span>
  </div>
  <div class="kv">
    <b>解析出的身份</b>
    <span class="mono">
      <?php if ($currentUid === null): ?>
        (无效凭据 —— 视为未登录)
      <?php else: ?>
        uid=<?= htmlspecialchars((string) $currentUid) ?>
        （<?= htmlspecialchars(session_username($currentUid)) ?>）
      <?php endif; ?>
    </span>
  </div>
  <p class="hint" style="margin:12px 0 0">
    「不可读」和「不可伪造」是两件事。上面这串字符，客户端解得开，也编得回去。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">我的订单</h3>
  <?php if ($currentUid === null): ?>
    <p style="margin:0;color:var(--muted);font-size:14px">
      未携带有效的 <code>Cookie: sid</code>，无法确定身份。
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
  <form method="get" action="medium.php">
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
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>上面那张卡片把 <code>sid</code> 解码后的明文直接显示出来了 —— 它是什么？</li>
    <li>既然能解出来，能不能改掉再编回去？</li>
    <li>这一档的 SQL 是对的。那么越权成立的时候，到底是哪一环失败了？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/idor-session.md</code>。</p>
</div>

<?php layout_footer(); ?>
