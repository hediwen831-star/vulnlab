<?php
/**
 * 越权（IDOR）· medium 档 —— 校验了归属，但「我是谁」是客户端说的
 *
 * 防护方式：加了归属校验 —— 查询时带上 `user_id` 条件。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 这一档「看起来已经修好了」
 * ══════════════════════════════════════════════════════════════════
 *
 * 对比 low 档那一行，这里多了归属条件：
 *
 *     low    ：WHERE id = ?
 *     medium ：WHERE id = ? AND user_id = ?      ← 加了
 *
 * 从 SQL 的角度看，防护确实到位了 —— 不是本人查不到。
 * 问题在于**第二个问号填的是什么**：
 *
 *     $uid = (int) ($_REQUEST['uid'] ?? 0);      ← 从请求里读
 *
 * 也就是说：**「我是谁」这个信息由客户端提供。**
 *
 * 于是攻击者只要把 `uid` 改成 3，就变成了 bob，
 * 然后就能名正言顺地查到 bob 的订单 —— 归属校验**正常工作了**，
 * 它只是被喂了一个假的身份。
 *
 * ══════════════════════════════════════════════════════════════════
 * 这个漏洞的形状值得单独记住
 * ══════════════════════════════════════════════════════════════════
 *
 * 前九个场景里，漏洞都是「某个检查被绕过了」。
 * 这一档不是 —— **检查没有被绕过，它通过了。**
 *
 *     校验代码：if ($order['uid'] === $uid)  →  3 === 3  →  通过
 *
 * 校验本身没有任何问题。出问题的是**输入给校验的那个值从哪来**。
 *
 * 换句话说：
 *
 *     **校验的正确性，取决于它所依据的那个信息的可信度。**
 *
 *     依据一个客户端能随意设置的值去做权限判断，
 *     等于没有做权限判断 —— 只是多写了几行代码。
 *
 * ── 这个错误在真实项目里长什么样 ──
 *
 * 它不总是 `uid` 这个参数名。常见的形态有：
 *
 *     · 网关注入的请求头（`X-User-Id`）—— 但直连应用服务器时可以自己填
 *     · 客户端传来的 `user_id` / `account` / `tenant_id`
 *     · 藏在 Cookie 里的「明文身份」（没有签名）
 *     · JWT 里未经验证的字段（没有校验签名就读 `sub`）
 *
 * 共同点是：**这个值来自请求方，而不是服务端自己算出来的。**
 *
 * 而 high 档的做法只有一个字之差 —— 值的来源换成了服务端自己：
 *
 *     $uid = CURRENT_UID;   // 相当于 $_SESSION['uid']
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/store.php';

$orderId = isset($_REQUEST['order_id']) ? trim((string) $_REQUEST['order_id']) : '';
// ----------------------------------------------------------------------
// 漏洞点：从请求里读「我是谁」
//
// $_REQUEST 同时接受 GET 和 POST —— 这让构造请求更省事，
// 但也意味着身份可以被放在 URL 里、表单里、Cookie 里，
// 攻击者有多种投递方式。
// ----------------------------------------------------------------------
$claimedUid = isset($_REQUEST['uid']) ? (int) $_REQUEST['uid'] : null;

$submitted = ($orderId !== '');
$order = null;
$error = '';
$isOwner = false;
$sqlShown = '';

if ($submitted) {
    // 没传 uid 时，服务端「好心」地退回到当前会话的身份 ——
    // 这个回落逻辑让不传 uid 的正常请求也能工作
    $effectiveUid = $claimedUid ?? CURRENT_UID;

    $sqlShown = 'SELECT * FROM orders WHERE id = ' . $orderId
        . ' AND user_id = ' . $effectiveUid;

    // 归属校验在这里 —— 代码本身完全正确
    $order = idor_find_order($orderId, $effectiveUid);

    if ($order === null) {
        $error = '订单不存在，或不属于当前用户。';
    } else {
        $isOwner = ((int) $order['uid'] === CURRENT_UID);
    }
}
?>
<?php layout_header(
    '越权（IDOR）· 难度 medium',
    '归属校验没有被绕过 —— 它通过了。问题在于「我是谁」是请求方自己说的。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0"><span class="c">// 加了归属条件 —— 这一行是对的</span>
$order = <span class="v">idor_find_order</span>($orderId, $uid);
<span class="c">//   SELECT * FROM orders WHERE id = ? AND user_id = ?</span>

<span class="c">// 但第二个问号填的是这个：</span>
$uid = (<span class="k">int</span>) $_REQUEST[<span class="s">'uid'</span>];   <span class="c">// ← 从请求里读「我是谁」</span></pre>
  <p style="margin:10px 0 0;font-size:14px;color:var(--muted)">
    <b>校验没有被绕过，它通过了。</b>
    <code>3 === 3</code> —— 校验代码本身没有任何问题。<br>
    出问题的是：那个 <code>3</code> 是<b>请求方自己说的</b>。
  </p>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    当前登录用户仍然是 <code><?= htmlspecialchars(CURRENT_USER) ?></code>。<br>
    这次直接改 <code>order_id</code> 会被挡下 —— 找到这一档真正依赖的东西。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">我的订单</h3>
  <div class="links">
    <?php foreach (['1001' => '1001（机械键盘）', '1002' => '1002（显示器支架）'] as $id => $label): ?>
      <a href="?order_id=<?= urlencode((string) $id) ?>"><?= htmlspecialchars($label) ?></a>
    <?php endforeach; ?>
  </div>
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
    <?php render_order($order, $isOwner); ?>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">核心绕过点：身份的来源</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:18%">档位</th><th style="width:40%">归属校验</th><th>「我是谁」从哪来</th></tr></thead>
      <tbody>
        <tr>
          <td>low</td>
          <td class="mono" style="color:var(--danger)">没有</td>
          <td>——（不需要知道是谁）</td>
        </tr>
        <tr>
          <td>medium</td>
          <td class="mono" style="color:var(--ok)">有，而且写对了</td>
          <td style="color:var(--danger)"><b>请求参数 <code>uid</code></b> —— 客户端说自己是几就是几</td>
        </tr>
        <tr>
          <td>high</td>
          <td class="mono" style="color:var(--ok)">有，而且写对了</td>
          <td style="color:var(--ok)"><b>服务端会话</b>（<code>$_SESSION['uid']</code>）—— 请求方改不了</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="hint">
    <b>medium 和 high 的区别只有一个字：值的来源。</b><br>
    校验逻辑一模一样，SQL 一模一样，代码行数几乎一样 ——
    但一个能被一张 URL 攻破，另一个不能。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>这一档的归属校验是怎么写的？它拿什么和订单的 <code>uid</code> 比？</li>
    <li>那个被拿来比较的值，是服务端自己知道的，还是请求里带的？</li>
    <li>看页面上的「服务端执行的查询」—— 第二个绑定值是什么？</li>
    <li>想一个更大的问题：**服务端凭什么知道你 uid 是几？**
        如果这个答案里出现了「请求」「参数」「请求头」任何一个词，那就是漏洞。</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/idor.md</code>。</p>
</div>

<?php layout_footer(); ?>
