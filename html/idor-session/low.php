<?php
/**
 * 会话凭据 · low 档 —— 详情接口忘了校验归属
 *
 * 身份来源：`Cookie: sid=<uid 明文>`（改一个数字就变成别人）
 * 归属校验：**详情接口没有**，而「我的订单」列表有
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 「列表有过滤、详情没有」是这类漏洞最常见的长相
 * ══════════════════════════════════════════════════════════════════
 *
 * 打开这个页面，「我的订单」只列出你自己的两条 —— 看起来一切正常，
 * 让人以为权限控制已经做了。
 *
 * 但那是**列表查询**里的一个 WHERE 条件。详情接口是另一个查询，
 * 而它长这样：
 *
 *     列表：SELECT * FROM orders WHERE user_id = ?      ← 有过滤
 *     详情：SELECT * FROM orders WHERE id = ?           ← 没有
 *
 * 同一个页面，两个查询，一个写了一个没写。
 *
 * 这不是「开发者不知道要做权限校验」——他知道，列表那里就写了。
 * 这是**同一条安全规则在两个地方被实施，只落地了一处**。
 * 真实项目里凡是「同一种校验需要重复写多次」的地方，都是这个形状。
 *
 * ── 顺便：这一档的 Cookie 也不可信 ──
 *
 * `sid` 是明文 uid，客户端改一个数字就能冒充别人。
 * 但注意：**即使把 Cookie 换成不可伪造的会话令牌，这一档的漏洞依然成立** ——
 * 因为问题出在「忘了校验归属」，与凭据强度无关。
 *
 * 两个问题是独立的。medium 档会把「凭据可伪造」单独拎出来讲。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/store.php';

// ----------------------------------------------------------------------
// 身份解析：Cookie 里的 sid 就是 uid 明文
//
// 服务端做的全部处理是 (int) 转换。这一步不是校验，
// 只是把字符串变成数字 —— 它挡不住任何东西。
// ----------------------------------------------------------------------
$rawSid = isset($_COOKIE['sid']) ? trim((string) $_COOKIE['sid']) : null;
$currentUid = null;
if ($rawSid !== null && $rawSid !== '') {
    $candidate = (int) $rawSid;
    if (isset(SESSION_USERS[$candidate])) {
        $currentUid = $candidate;
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
    // 漏洞点：这个查询里没有「这条订单属于谁」的条件
    //
    // 对比「我的订单」列表那个查询 —— 那个是带了 user_id 条件的。
    // 两处用的都是同一张表、同一个业务规则，只是这里漏了。
    // ------------------------------------------------------------------
    $sqlShown = 'SELECT * FROM orders WHERE id = ' . $orderId;
    $order = session_find_order($orderId, null);

    if ($order === null) {
        $error = '订单不存在。';
    } else {
        $isOwner = ($currentUid !== null && (int) $order['uid'] === $currentUid);
    }
}

// 「我的订单」—— 这个查询是**带了**归属条件的（正常业务功能）
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
    '会话凭据 · 难度 low',
    '「我的订单」列表过滤了归属，详情接口忘了 —— 同一条规则只落地了一处。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    水平越权能读到其他用户的全部数据。真实授权测试中，越权验证应当<b>只读取「刚好够证明问题」的数据</b>，
    不要批量遍历、不要下载真实用户资料。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的两个查询</h3>
  <pre style="margin:10px 0 0"><span class="c">// 「我的订单」列表 —— 有归属条件</span>
SELECT * FROM orders WHERE <span class="v">user_id</span> = ?

<span class="c">// 订单详情 —— 没有</span>
SELECT * FROM orders WHERE id = ?
<span class="c">//                       ↑ 少了 AND user_id = ?</span></pre>
  <p class="hint" style="margin:12px 0 0">
    身份来源：<code>Cookie: sid</code> 的值直接就是 uid。改数字即可切换身份。
  </p>
</div>

<?php render_session_identity($currentUid, $rawSid); ?>

<div class="card">
  <h3 style="margin-top:0">我的订单</h3>
  <?php if ($currentUid === null): ?>
    <p style="margin:0;color:var(--muted);font-size:14px">
      未携带有效的 <code>Cookie: sid</code>，无法确定身份。
      参考值：<code>sid=2</code>（alice）、<code>sid=3</code>（bob）、<code>sid=4</code>（carol）。
    </p>
  <?php else: ?>
    <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
      （这个列表是服务端按当前用户过滤后的结果，属于正常的业务功能）
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
  <form method="get" action="low.php">
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
    <li>「我的订单」列表是怎么知道你只有那两条的？那个条件用在详情接口上了吗？</li>
    <li>把 <code>order_id</code> 换成 <code>1003</code>（bob 的订单）会发生什么？</li>
    <li>同样的请求，把 <code>Cookie: sid</code> 改成 <code>3</code> 又会发生什么？两次的差别说明什么？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/idor-session.md</code>。</p>
</div>

<?php layout_footer(); ?>
