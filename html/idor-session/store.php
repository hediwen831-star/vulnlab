<?php
/**
 * 会话凭据可伪造场景 —— 三档共用的数据与渲染。
 *
 * ══════════════════════════════════════════════════════════════════
 * 这个场景和 idor 场景的区别
 * ══════════════════════════════════════════════════════════════════
 *
 * idor 场景问的是：**服务端有没有校验资源归属**。
 *
 * 这个场景问的是另一个问题：**服务端凭什么相信「你是谁」**。
 *
 * 两件事经常被混为一谈，但它们独立：
 *
 *     · 归属校验写了，但身份凭据可以伪造  → 越权仍然成立
 *     · 归属校验没写，但身份无法伪造      → 越权同样成立
 *
 * 三档分别对应「身份凭据」的三种可信度：
 *
 *     low    ：`sid` 就是明文 uid。客户端改一个数字就成了别人
 *     medium ：`sid` 是 base64(uid)。**编码被当成了签名**
 *     high   ：`sid` 是随机令牌，服务端用自己持有的映射表还原 uid
 *
 * ── 为什么单独做一个场景 ──
 *
 * 因为真实项目里这三种形态都极常见，而且中间那种（base64 / hex / 自定义
 * 编码被当成防护）最容易被误判为「已经做了安全处理」——
 * 它看起来不像明文，于是评审时容易被放过。
 *
 * 判别方法只有一条：**凭据里的信息，客户端能不能自己造出来。**
 * 能造出来的，就不是凭据。
 */

declare(strict_types=1);

/** 通关凭证 —— 放在 bob 的订单备注里，只有越权读到它才能拿到 */
const SESSION_FLAG = 'VULNLAB{session_credential_unverified}';

/**
 * 用户表 —— 与 idor 场景保持同一批用户，便于对照理解。
 */
const SESSION_USERS = [
    2 => 'alice',
    3 => 'bob',
    4 => 'carol',
];

/**
 * 订单表。
 *
 * note 字段是「只有订单拥有者才该看到」的内容 —— bob 的订单里放着通关凭证，
 * 于是「有没有越权」变成一个非黑即白的判定：看得到凭证 = 越权成立。
 */
const SESSION_ORDERS = [
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
    [
        'id'     => '1003',
        'uid'    => 3,
        'owner'  => 'bob',
        'item'   => '（bob 的私人订单）',
        'amount' => '1299',
        'note'   => SESSION_FLAG . ' —— 这条备注只有订单拥有者能看到。',
    ],
    [
        'id'     => '1004',
        'uid'    => 4,
        'owner'  => 'carol',
        'item'   => '（carol 的订单）',
        'amount' => '89',
        'note'   => '内部审计相关，非本人不应可见。',
    ],
];

/**
 * high 档专用：随机会话令牌 → uid 的映射表。
 *
 * ⚠️ 这张表在**服务端**。客户端只拿到令牌本身，
 * 拿不到「令牌是怎么算出来的」—— 因为它不是算出来的，是随机发的。
 *
 * 这正是它和 medium 档的分界：medium 的 sid 客户端可以自己造，
 * high 的 sid 客户端造不出来（除非拿到别人的令牌）。
 */
const SESSION_TOKENS = [
    'a1b2c3d4e5f6' => 2,   // alice 的令牌
    'f7e8d9c0b1a2' => 3,   // bob 的令牌
    '3c4d5e6f7a8b' => 4,   // carol 的令牌
];

/**
 * 按条件查订单。
 *
 * @param string   $orderId  订单号
 * @param int|null $ownerUid 不为 null 时只返回属于该用户的订单
 *
 * @return array<string,string>|null
 */
function session_find_order(string $orderId, ?int $ownerUid = null): ?array
{
    foreach (SESSION_ORDERS as $order) {
        if ($order['id'] !== $orderId) {
            continue;
        }
        // 这一行就是「有没有做归属校验」的分界
        if ($ownerUid !== null && (int) $order['uid'] !== $ownerUid) {
            return null;
        }
        return $order;
    }
    return null;
}

/**
 * 按 uid 取用户名；未知 uid 返回「未知用户」。
 */
function session_username(?int $uid): string
{
    if ($uid === null || !isset(SESSION_USERS[$uid])) {
        return '未知用户';
    }
    return SESSION_USERS[$uid];
}

/**
 * 渲染「当前身份」卡片。
 *
 * 把服务端**实际用到的** uid 和凭据原文都摊开显示 ——
 * 这样改 Cookie 之后能立刻看出服务端认成了谁。
 *
 * @param int|null    $effectiveUid 服务端最终采用的 uid
 * @param string|null $rawCredential 请求里带的凭据原文（用于对比展示）
 */
function render_session_identity(?int $effectiveUid, ?string $rawCredential): void
{
    ?>
    <div class="card">
      <h3 style="margin-top:0">服务端认为你是谁</h3>
      <div class="kv">
        <b>请求里的凭据</b>
        <span class="mono"><?= $rawCredential === null ? '(未携带 Cookie: sid)' : htmlspecialchars($rawCredential) ?></span>
      </div>
      <div class="kv">
        <b>解析出的身份</b>
        <span class="mono">
          <?php if ($effectiveUid === null): ?>
            (无效凭据 —— 视为未登录)
          <?php else: ?>
            uid=<?= htmlspecialchars((string) $effectiveUid) ?>
            （<?= htmlspecialchars(session_username($effectiveUid)) ?>）
          <?php endif; ?>
        </span>
      </div>
      <p class="hint" style="margin:12px 0 0">
        Cookie 是客户端自己发的 —— 服务端看到的永远只是「请求里写了什么」。
      </p>
    </div>
    <?php
}

/**
 * 渲染订单详情卡片。
 *
 * @param array<string,string> $order
 * @param bool                 $isOwner 订单是否属于服务端认定的当前用户
 */
function render_session_order(array $order, bool $isOwner): void
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
          ★ 你看到了一条<b>不属于你</b>的订单备注 —— 越权成立
        </p>
      <?php elseif ($isOwner): ?>
        <p class="hint" style="margin:14px 0 0">
          这是你自己的订单。
        </p>
      <?php endif; ?>
    </div>
    <?php
}
