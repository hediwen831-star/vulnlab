<?php
/**
 * 越权（IDOR）· high 档 —— 修复对照
 *
 * 修复方式：**身份只从服务端取 + 归属条件进查询 + 订单号不可枚举 + 不泄漏存在性。**
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码的修复版，请勿删改其中的防护逻辑。
 *
 * ══════════════════════════════════════════════════════════════════
 * 前两档的失败模式
 * ══════════════════════════════════════════════════════════════════
 *
 *   low    ：查询里没有归属条件 —— 拿到 ID 就能看
 *   medium ：有归属条件，但「我是谁」来自请求参数 `uid`
 *            —— 校验没被绕过，它只是被喂了个假身份
 *
 * 两档的共同点是：**归属判断依据的信息，不是服务端自己产出的。**
 *
 *   low    ：压根没有依据（没有依据 = 不做判断）
 *   medium ：依据是客户端给的
 *
 * ══════════════════════════════════════════════════════════════════
 * 四层防护
 * ══════════════════════════════════════════════════════════════════
 *
 *   ① 身份只从服务端会话取
 *
 *      这一条是根本。「我是谁」必须由服务端自己确定 ——
 *      从会话、从校验通过的 token、从服务端签发的凭据。
 *
 *      **判断标准很简单：这个值在不在请求里？**
 *      在 → 不能用来做权限判断（直接删掉这个参数）。
 *
 *   ② 归属条件写进查询本身
 *
 *      注意对比下面这行和 low 档的那一行 —— 差别只有 `AND user_id = ?`：
 *
 *          low  ：SELECT * FROM orders WHERE id = ?
 *          high ：SELECT * FROM orders WHERE id = ? AND user_id = ?
 *
 *      把它写进 WHERE，而不是「查出来之后用 if 判断一下」——
 *      后者很容易在某个分支里被漏掉，前者不可能被绕过。
 *
 *   ③ 订单号不可枚举
 *
 *      low / medium 用 `1003` 这种短数字——攻击者可以遍历。
 *      high 用 `ord_7f3a9c2e5b` 这种随机串。
 *
 *      ⚠️ 这一层是**纵深防御，不是替代品**！
 *      如果 ① ② 没做，随机 ID 只是拖慢攻击者 ——
 *      因为 ID 会从别的地方泄露（分享链接、日志、接口响应、邮件）。
 *      **不可枚举永远不能代替权限校验。**
 *
 *   ④ 越权时返回「不存在」而不是「无权限」
 *
 *      如果返回「无权访问」，攻击者就能区分：
 *          无权限  → 这个订单存在
 *          不存在  → 这个订单不存在
 *      于是可以靠遍历枚举出「哪些 ID 是有效的」。
 *      返回统一的「不存在」，把这两种情况合并掉。
 *
 *      这就是 Authorization 与 Information Disclosure 的交界 ——
 *      **权限判断本身也会泄漏信息。**
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
$audit = [];

// ----------------------------------------------------------------------
// 层 ①：身份只从服务端取
//
// 注意这里**完全没有读 $_GET / $_POST / $_REQUEST / $_COOKIE 里的身份**。
// 真实项目里这一行是：
//
//     $sessionUid = (int) ($_SESSION['uid'] ?? 0);
//     if ($sessionUid === 0) { /* 未登录，跳转登录页 */ }
//
// 关键不在于写法，在于**这个值的来源不是请求**。
// ----------------------------------------------------------------------
$sessionUid = CURRENT_UID;
$audit[] = [
    '① 身份来源',
    '服务端会话（uid=' . $sessionUid . '）',
    '✓ 与请求参数无关',
];

if ($submitted) {
    // 请求里如果带了 uid，本档的选择是：**忽略它，并记录下来**
    //
    // 为什么要「记录下来」而不是静默忽略：
    // 正常业务不会往这个接口传 uid。带了这个参数，
    // 说明要么是攻击者在试探，要么是前端代码里残留了旧的调用 ——
    // 两种情况都值得进日志。
    if (isset($_REQUEST['uid'])) {
        $audit[] = [
            '① 身份来源',
            '请求里带了 uid=' . (string) $_REQUEST['uid'],
            '— 已忽略（身份不取自请求参数）',
        ];
    }

    // 层 ③：订单号不可枚举
    //
    // 反查一下这个不透明 ID 对应哪条订单 —— 用映射表而不是直接用它当主键，
    // 是为了让「ID 不可枚举」这件事和「归属校验」解耦：
    // 前者是纵深防御，后者才是真正的防线。
    $realId = null;
    foreach (IDOR_OPAQUE_IDS as $plain => $opaque) {
        if (hash_equals($opaque, $orderId)) {
            // ⚠️ (string) 不能省：PHP 会把「数字形式的字符串键」自动转成整数，
            // 所以 $plain 是 int —— strict_types 下把它传给要求 string 的函数
            // 会直接抛 TypeError（这个坑实测踩过）。
            $realId = (string) $plain;
            break;
        }
    }

    if ($realId === null) {
        $audit[] = ['③ 订单号', substr($orderId, 0, 24), '✗ 不可枚举 ID 校验失败'];
    } else {
        $audit[] = ['③ 订单号', substr($orderId, 0, 24), '✓ 有效 ID'];
    }

    // ------------------------------------------------------------------
    // 层 ②：归属条件写进查询本身
    //
    // 注意传了 $sessionUid —— 这个值来自服务端，请求方改不了。
    // 归属过滤发生在**查询内部**，不存在「查出来之后忘了判断」的可能。
    // ------------------------------------------------------------------
    if ($realId !== null) {
        $order = idor_find_order($realId, $sessionUid);
        $audit[] = [
            '② 归属校验',
            'WHERE id = ? AND user_id = ' . $sessionUid,
            $order === null ? '✗ 该订单不属于当前用户' : '✓ 归属正确',
        ];
        $isOwner = ($order !== null);
    }

    // ------------------------------------------------------------------
    // 层 ④：不泄漏「订单是否存在」
    //
    // 三种情况统一返回同一句话：
    //   · 订单号无效
    //   · 订单存在但不属于你
    //   · 订单存在且属于你 —— 这个当然返回正常内容
    //
    // 前两种合并成一句「订单不存在」，攻击者就无法通过响应差异
    // 判断某个 ID 是否真实存在。
    // ------------------------------------------------------------------
    if ($order === null) {
        $error = '订单不存在。';
    }
}
?>
<?php layout_header(
    '越权（IDOR）· 难度 high（已修复）',
    '归属校验的依据必须来自服务端 —— 这条一条就够了，其余三层是纵深防御。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护（四层）</h3>
  <pre style="margin:10px 0 0;background:#064e3b"><span class="c">// ① 身份只从服务端取 —— 请求里根本没有这个信息</span>
$sessionUid = CURRENT_UID;   <span class="c">// 真实项目：$_SESSION['uid']</span>

<span class="c">// ② 归属条件写进查询本身</span>
<span class="c">//   low   : WHERE id = ?</span>
<span class="c">//   high  : WHERE id = ? AND user_id = :session_uid</span>

<span class="c">// ③ 订单号不可枚举（纵深防御，不能替代 ①②）</span>
'ord_7f3a9c2e5b'   <span class="c">// 而不是 1003</span>

<span class="c">// ④ 越权时统一返回「不存在」，不泄漏订单是否存在</span>
$error = <span class="s">'订单不存在。'</span>;</pre>
  <p style="margin:10px 0 0;font-size:14px;color:#065f46">
    <b>① 是根本，② 是执行，③④ 是纵深。</b><br>
    只做 ③（随机 ID）不做 ①②，等于把门锁藏在门后面 ——
    ID 会从分享链接、日志、接口响应里漏出去，而权限校验不会。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">我的订单</h3>
  <div class="links">
    <?php foreach (['1001' => '机械键盘', '1002' => '显示器支架'] as $plain => $label): ?>
      <a href="?order_id=<?= urlencode(IDOR_OPAQUE_IDS[$plain]) ?>">
        <?= htmlspecialchars($label) ?>
      </a>
    <?php endforeach; ?>
  </div>
  <p class="hint" style="margin:12px 0 0">
    注意链接里的订单号是<b>随机串</b>，不是 <code>1001</code>。
    真实项目里也常这么做（UUID / 短码），但要清楚：
    <b>这不能替代权限校验</b>。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">查询订单详情</h3>
  <form method="get" action="high.php">
    <div class="row">
      <label style="min-width:90px">订单号</label>
      <input type="text" name="order_id" style="flex:1;font-family:var(--mono)"
             value="<?= htmlspecialchars($orderId) ?>" placeholder="ord_...">
    </div>
    <div class="row">
      <button type="submit">查询</button>
    </div>
  </form>
  <p class="hint" style="margin:10px 0 0">
    试试把 <code>uid=3</code> 加到 URL 后面，或者把订单号换成 <code>1003</code>
    —— 前者被忽略，后者查不到。
  </p>
</div>

<?php if ($submitted): ?>
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

  <?php if ($error !== ''): ?>
    <div class="card">
      <p style="margin:0;color:var(--danger);font-weight:500"><?= htmlspecialchars($error) ?></p>
      <p class="hint" style="margin:10px 0 0">
        注意这句话是「不存在」，不是「无权限」——
        <b>「存在但无权」和「不存在」返回同样的结果，攻击者就无法靠遍历枚举出有效 ID。</b>
      </p>
    </div>
  <?php else: ?>
    <?php render_order($order, $isOwner); ?>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">攻击载荷对照（都被挡住）</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:44%">载荷</th><th>被哪一层挡住</th></tr></thead>
      <tbody>
        <tr>
          <td class="mono" style="font-size:12.5px">?order_id=1003（low 的手法）</td>
          <td style="font-size:13px;color:var(--muted)">层 ③（不是有效的不可枚举 ID）</td>
        </tr>
        <tr>
          <td class="mono" style="font-size:12.5px">?order_id=ord_b5c1e93d74（bob 的真实 ID）</td>
          <td style="font-size:13px;color:var(--muted)">
            层 ②（ID 有效，但不属于当前用户）<br>
            <span style="opacity:.75">
              ⚠️ 这一条很重要 —— 它说明防护**不是靠「猜不到 ID」实现的**。
              就算 ID 泄露了，层 ② 依然挡住。
            </span>
          </td>
        </tr>
        <tr>
          <td class="mono" style="font-size:12.5px">?order_id=ord_b5c1e93d74&amp;uid=3（medium 的手法）</td>
          <td style="font-size:13px;color:var(--muted)">
            层 ①（<code>uid</code> 被忽略 —— 身份不取自请求参数）+ 层 ② 继续生效
          </td>
        </tr>
        <tr>
          <td class="mono" style="font-size:12.5px">?order_id=ord_7f3a9c2e5b（自己的单）</td>
          <td style="font-size:13px;color:var(--ok)">✓ 正常返回</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="hint">
    第 2 行值得单独看：<b>知道别人订单号 ≠ 能看别人订单。</b><br>
    这是本档与 low / medium 的根本差别 ——
    前两档只要知道 ID 就够了，这一档知道 ID 也没用。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">修复要点总结</h3>
  <ol style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>身份只能来自服务端</b> —— 会话 / 已校验的 token / 服务端签发的凭据。
      <b>判据：这个值在不在请求里？在 → 就不能用来做权限判断。</b>
    </li>
    <li>
      <b>归属条件写进查询</b> ——
      `WHERE id = ? AND user_id = ?`，而不是「查出来之后用 if 判断一下」。
      后者可能在某个分支里被漏掉，前者不可能被绕过
    </li>
    <li>
      <b>把「谁能访问」和「访问什么」绑在一起校验</b> ——
      任何「先取资源、再判断权限」的写法，都要问一句：
      <b>中间有没有别的路径能拿到这个资源？</b>
    </li>
    <li>
      <b>不可枚举 ID 只作为纵深防御</b> ——
      它能拖慢攻击者，但 ID 会从别处泄露。
      **永远不能用它替代权限校验**
    </li>
    <li>
      <b>越权时不要泄漏「存在性」</b> ——
      统一返回「不存在」，把「存在但无权」和「不存在」合并
    </li>
    <li>
      <b>所有接口都要过一遍授权清单</b> ——
      越权最常见的成因不是「写错了」，而是**某个接口忘了写**。
      所以需要一个显式的清单：这个接口谁能访问、依据是什么。
      清单本身就是可审查的
    </li>
    <li>
      <b>别只用 ID 做对象引用</b> ——
      如果业务上能接受，用「当前用户的资源列表里第 N 项」
      或者带签名的一次性 token，比裸 ID 更安全
    </li>
  </ol>
  <p class="hint">
    最容易踩的一条：<b>「我的 ID 是随机的 / 是 UUID，所以不会有越权」。</b><br>
    随机 ID 降低的是「被猜中」的概率，而越权漏洞的本质是
    <b>「服务端没检查这个资源属不属于你」</b> ——
    这两件事没有因果关系。ID 会泄露：分享链接、浏览器历史、
    日志、Referer 头、接口响应、邮件里的链接……
    <b>一旦泄露，随机 ID 就退化成普通 ID。</b>
  </p>
</div>

<?php layout_footer(); ?>
