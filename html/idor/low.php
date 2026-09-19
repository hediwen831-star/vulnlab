<?php
/**
 * 越权（IDOR）· low 档 —— 拿到订单号就能查，不校验归属
 *
 * 漏洞成因：接口只验证「这个订单存不存在」，不验证「这个订单是不是你的」。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 越权和前面所有场景的根本区别
 * ══════════════════════════════════════════════════════════════════
 *
 * 前面九个场景里的每一个，攻击者都在做「服务端不希望他做的事」：
 * 注入 SQL、执行命令、读文件、伪造签名……
 *
 * 越权不是这种形态。在这个场景里，攻击者做的每一件事
 * **都是系统正常提供的功能**：
 *
 *     访问 /idor/low.php?order_id=1003
 *     ↓
 *     系统正常地查询数据库、正常地返回订单、正常地渲染页面
 *
 * 没有任何一行代码「被绕过了」，也没有任何过滤「被绕过了」。
 * 问题在于：**系统压根没打算区分「这个订单是谁的」。**
 *
 * ── 一句话概括 ──
 *
 * **认证（Authentication）回答「你是谁」，
 *  授权（Authorization）回答「你能做什么」。**
 *
 * 越权漏洞属于后者 —— 而「忘了做授权」和「授权写错了」
 * 在代码里都不会报错、不会有异常、单测也测不出来（因为功能是「正常」的）。
 *
 * ══════════════════════════════════════════════════════════════════
 * 为什么它在真实世界里排第一
 * ══════════════════════════════════════════════════════════════════
 *
 * OWASP Top 10 (2021) 的 A01 就是「失效的访问控制」。
 * 它之所以排第一，有两个很实际的原因：
 *
 *   ① **自动化扫描器很难发现它** —— 扫描器不知道「1003 号订单该属于谁」，
 *      没有 SQL 报错、没有异常响应、没有可识别的特征。
 *      它需要**理解业务语义**才能判断，而这正是工具做不到的。
 *
 *   ② **它的形态极其多样** —— 换个参数名、换个接口、换个 HTTP 方法，
 *      就可能是一个新的越权点。没有「一种通用的绕过写法」可以套用。
 *
 * 这两点合起来意味着：**越权只能靠人工测，而且必须理解业务。**
 * 也正因为如此，它是最值得花时间的一类漏洞。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/store.php';

$orderId = isset($_GET['order_id']) ? trim((string) $_GET['order_id']) : '';
$submitted = ($orderId !== '');

$order = null;
$error = '';
$isOwner = false;
$sqlShown = '';

if ($submitted) {
    // ------------------------------------------------------------------
    // 漏洞点：只按订单号查，不带任何归属条件
    //
    // 对比一下 high 档的那一行：
    //
    //     high  ：WHERE order_id = ? AND user_id = :session_uid
    //     low   ：WHERE order_id = ?
    //
    // 差别就是 **一个 WHERE 条件**。而这一条之差，
    // 就是「功能正常」和「能读所有人的订单」之间的距离。
    //
    // 注意这行代码本身没有任何「错误」——
    // 按 ID 查一条记录是完全正常的写法。
    // 缺的是那个**业务上必须存在**的约束。
    // ------------------------------------------------------------------
    $sqlShown = 'SELECT * FROM orders WHERE id = ' . $orderId;
    $order = idor_find_order($orderId, null);

    if ($order === null) {
        $error = '订单不存在。';
    } else {
        // 注意：这里算出了 isOwner，但只用来显示一行提示 —— 不参与任何判断
        $isOwner = ((int) $order['uid'] === CURRENT_UID);
    }
}

?>
<?php layout_header(
    '越权（IDOR）· 难度 low',
    '接口只问「这个订单存在吗」，没问「这个订单是你的吗」。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    水平越权能读到其他用户的全部数据；垂直越权则能拿到管理员权限。
    真实授权测试中，越权验证应当<b>只读取「刚好够证明问题」的数据</b>，
    不要批量遍历、不要下载真实用户资料。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$order = <span class="v">idor_find_order</span>($orderId);   <span class="c">// 只按订单号查</span>
<span class="c">// 等价的 SQL：</span>
<span class="c">//   SELECT * FROM orders WHERE id = ?</span>
<span class="c">//                        ↑ 就少了这个 AND</span>
<span class="c">//   SELECT * FROM orders WHERE id = ? AND user_id = :session_uid</span></pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    当前登录用户是 <code><?= htmlspecialchars(CURRENT_USER) ?></code>（uid=<?= CURRENT_UID ?>）。<br>
    找到 <b>bob 的订单</b>，读出里面的备注 —— 通关凭证在里面。
  </p>
  <p class="hint" style="margin:12px 0 0">
    订单号是短数字，而且看起来是连续的。
    真实场景里的 ID 通常就是这样 —— 自增主键、可预测的流水号。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">我的订单</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    （这个列表是服务端按当前用户过滤后的结果，属于正常的业务功能）
  </p>
  <div class="links">
    <?php foreach (['1001' => '1001（机械键盘）', '1002' => '1002（显示器支架）'] as $id => $label): ?>
      <a href="?order_id=<?= urlencode((string) $id) ?>"><?= htmlspecialchars($label) ?></a>
    <?php endforeach; ?>
  </div>
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
    <?php render_order($order, $isOwner); ?>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>这个接口判断「能不能看」时，看了哪些东西？（提示：只有一个订单号）</li>
    <li>「我的订单」列表是按什么过滤的？那个过滤条件能不能用在详情接口上？</li>
    <li>如果订单号是连续的，把 <code>1001</code> 改成别的数字会发生什么？</li>
    <li>换个角度想：**服务端凭什么知道这个订单是你的？**（这个问题是越权场景的核心）</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/idor.md</code>。</p>
</div>

<?php layout_footer(); ?>
