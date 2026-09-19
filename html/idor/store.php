<?php
/**
 * 越权场景的共享数据 —— 三档共用。
 *
 * ══════════════════════════════════════════════════════════════════
 * 关于「当前登录用户」是怎么来的
 * ══════════════════════════════════════════════════════════════════
 *
 * 越权漏洞的核心问题是「服务端怎么确认你是谁」。
 * 所以这个场景必须先把这个问题的答案摆清楚 —— 三档的差异全在这里：
 *
 *   low    ：**不确认** —— 拿到订单号就查，不问你是谁
 *   medium ：确认了，但**身份来自请求参数**（`uid`）—— 客户端说自己是谁就是谁
 *   high   ：身份来自**服务端会话**（靶场用固定值模拟）
 *
 * ⚠️ 注意 `CURRENT_UID` 的位置和含义：
 *     它是**服务端自己知道**的信息，相当于真实项目里的
 *     `$_SESSION['uid']` 或 JWT 校验通过后的 `sub` 声明。
 *     它**从来不是**从请求里读来的 —— 这正是 high 档与 medium 档的分界。
 *
 * 靶场用固定值而不是真会话，是为了让 curl / Burp 不用处理 Cookie
 * 就能复现（和 CSRF 场景同一个取舍，理由也一样）。
 * 这个简化**不影响本场景的结论**：攻击者能不能改掉那个 uid，
 * 才是决定越权是否成立的关键。
 */

declare(strict_types=1);

/** 通关凭证 —— 放在 bob 的订单里，只有能越权读到它才能拿到 */
const IDOR_FLAG = 'VULNLAB{idor_horizontal_escalation}';

/**
 * 当前登录用户 —— 服务端自己知道的信息（模拟 $_SESSION['uid']）。
 *
 * ⚠️ 这个值在真实项目里来自会话 / 已校验的 token，**绝不能来自请求参数**。
 *    medium 档的漏洞就是「把这个值改成了从请求里读」。
 */
const CURRENT_UID = 2;
const CURRENT_USER = 'alice';

/**
 * 订单表。
 *
 * 注意 `note` 字段 —— 它是「只有订单拥有者才该看到」的内容。
 * bob 的订单里放着通关凭证，这样「有没有越权」就变成一个
 * 可判定的、非黑即白的结论：看得到凭证 = 越权成立。
 *
 * 三档的订单号故意不同：
 *   low / medium 用短数字（`1003`）—— 可以枚举，模拟「自增主键」
 *   high 用随机串（`ord_7f3a9c2e...`）—— 不可枚举，这是纵深防御的一层
 */
const IDOR_ORDERS = [
    // ── alice 自己的订单（对照组：正常能看）─────────────────────
    [
        'id'     => '1001',
        'uid'    => 2,
        'owner'  => 'alice',
        'item'   => '机械键盘',
        'amount' => '399',
        'note'   => '普通订单，无特殊内容。',
    ],
    [
        'id'     => '1002',
        'uid'    => 2,
        'owner'  => 'alice',
        'item'   => '显示器支架',
        'amount' => '159',
        'note'   => '普通订单，无特殊内容。',
    ],
    // ── bob 的订单（越权目标）───────────────────────────────────
    [
        'id'     => '1003',
        'uid'    => 3,
        'owner'  => 'bob',
        'item'   => '（bob 的私人订单）',
        'amount' => '1299',
        'note'   => IDOR_FLAG . ' —— 这条备注只有订单拥有者能看到。',
    ],
    // ── carol（审计员）的订单 ──────────────────────────────────
    [
        'id'     => '1004',
        'uid'    => 4,
        'owner'  => 'carol',
        'item'   => '（carol 的订单）',
        'amount' => '89',
        'note'   => '内部审计相关，非本人不应可见。',
    ],
];

/** high 档专用的订单号（随机、不可枚举）—— 与 IDOR_ORDERS 一一对应 */
const IDOR_OPAQUE_IDS = [
    '1001' => 'ord_7f3a9c2e5b',
    '1002' => 'ord_2d8e4a1f96',
    '1003' => 'ord_b5c1e93d74',
    '1004' => 'ord_9a6f27c8e3',
];

/**
 * 按条件查订单。
 *
 * @param string $orderId 订单号
 * @param int|null $ownerUid 若不为 null，则只返回属于该用户的订单
 *
 * @return array<string,string>|null 找到返回订单，找不到返回 null
 */
function idor_find_order(string $orderId, ?int $ownerUid = null): ?array
{
    foreach (IDOR_ORDERS as $order) {
        if ($order['id'] !== $orderId) {
            continue;
        }
        // 归属过滤 —— 这一行就是「有没有做水平越权防护」的分界
        if ($ownerUid !== null && (int) $order['uid'] !== $ownerUid) {
            return null;
        }
        return $order;
    }
    return null;
}

/** 渲染订单详情卡片 */
function render_order(array $order, bool $isOwner): void
{
    $hasFlag = strpos($order['note'], 'VULNLAB{') !== false;
    ?>
    <div class="card" style="<?= $hasFlag ? 'border-color:#fecaca;background:var(--danger-soft)' : '' ?>">
      <h3 style="margin-top:0">订单详情</h3>
      <div class="kv"><b>订单号</b><span class="mono"><?= htmlspecialchars($order['id']) ?></span></div>
      <div class="kv"><b>下单用户</b><span class="mono"><?= htmlspecialchars($order['owner']) ?></span></div>
      <div class="kv"><b>商品</b><span class="mono"><?= htmlspecialchars($order['item']) ?></span></div>
      <div class="kv"><b>金额</b><span class="mono">¥<?= htmlspecialchars($order['amount']) ?></span></div>
      <div class="kv"><b>备注</b><span class="mono" style="word-break:break-all"><?= htmlspecialchars($order['note']) ?></span></div>

      <?php if ($hasFlag): ?>
        <p style="margin:14px 0 0;color:var(--danger);font-weight:500">
          ★ 你看到了一条<b>不属于你</b>的订单备注 —— 水平越权成立
        </p>
      <?php elseif ($isOwner): ?>
        <p class="hint" style="margin:14px 0 0">
          这是你自己的订单（当前登录用户：<?= htmlspecialchars(CURRENT_USER) ?>）。
        </p>
      <?php endif; ?>
    </div>
    <?php
}
