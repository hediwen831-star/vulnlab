<?php
/**
 * CSRF · high 档 —— 修复对照
 *
 * 修复方式：**会话绑定的 token + 用过即换。**
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码的修复版，请勿删改其中的防护逻辑。
 *
 * ══════════════════════════════════════════════════════════════════
 * 前两档的失败模式
 * ══════════════════════════════════════════════════════════════════
 *
 *   low    ：什么都不检查
 *   medium ：检查 Referer —— 但 Referer 是「客户端自愿提供」的信息，
 *            攻击者既能去掉它（`no-referrer`），也能让一个包含目标域名的
 *            自己人域名把它带出来
 *
 * 两档的共同问题是同一个：
 *
 *   **它们依赖的信息，攻击者都能控制。**
 *
 *     · low 依赖「请求里的字段」→ 攻击者直接填
 *     · medium 依赖「Referer」→ 攻击者能选择不发，或者让域名带上那个串
 *
 * ══════════════════════════════════════════════════════════════════
 * 那什么信息是攻击者控制不了的？
 * ══════════════════════════════════════════════════════════════════
 *
 * 回到浏览器给攻击者划的那条线（同源策略）：
 *
 *   攻击者的页面能：让浏览器发出任意请求（表单 / img / fetch）
 *   攻击者的页面不能：**读取目标站点的响应内容**
 *
 * 所以只要满足两个条件，攻击者就无解：
 *
 *   ① 服务端把一个随机值放在**目标站点的页面里**（攻击者读不到）
 *   ② 提交时必须带上这个值，服务端比对
 *
 * 攻击者要伪造请求，就得填出这个随机值 —— 而他读不到它。
 * **这就是 CSRF token 的全部原理。**
 *
 * 注意「放在页面里」这个前提：如果 token 放在 Cookie 里，
 * 浏览器会自动带上它，攻击者发起的请求也会自动带上 —— 那就完全不起作用了。
 * **token 必须放在请求体/查询参数里，而不是自动携带的位置。**
 *
 * ══════════════════════════════════════════════════════════════════
 * 四层防护
 * ══════════════════════════════════════════════════════════════════
 *
 *   ① token 校验 —— 会话绑定、hash_equals 比较
 *   ② 一次性 —— 每次成功之后轮换 token，挡住重放
 *   ③ Referer / Origin 作为**额外的**信号（不能当作唯一防线）
 *   ④ 敏感操作二次确认（改邮箱后需要原密码 / 邮件确认）
 *
 * ③ 的位置很关键：**它是补充，不是替代。**
 *   本档把它留着，是为了说明「一条弱防线 + 一条强防线」是可以的，
 *   而「只有一条弱防线」（也就是 medium 档）不行。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/state.php';

if (isset($_GET['reset'])) {
    csrf_reset();
    header('Location: ' . basename(__FILE__));
    exit;
}

$state = csrf_load();
$submitted = false;
$changed = false;
$receivedEmail = '';
$receivedToken = '';
$audit = [];
$error = '';
$referer = (string) ($_SERVER['HTTP_REFERER'] ?? '');
$host = (string) ($_SERVER['HTTP_HOST'] ?? '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submitted = true;
    $receivedEmail = isset($_POST['email']) ? trim((string) $_POST['email']) : '';
    $receivedToken = isset($_POST['csrf_token']) ? (string) $_POST['csrf_token'] : '';

    // ------------------------------------------------------------------
    // 层 ①：token 校验
    //
    // 这个 token 是服务端生成的随机值，**只通过本站页面渲染出来**。
    // 攻击者的页面读不到它（同源策略），所以填不出来。
    //
    // 用 hash_equals 而不是 === ，理由和 JWT 场景一样：
    // 定长比较，避免通过响应时间逐字节猜 token。
    // ------------------------------------------------------------------
    if ($receivedToken === '') {
        $audit[] = ['① token 校验', '（未提交）', '✗ 缺少 token，拒绝'];
        $error = '请求被拒绝：缺少 CSRF token。';
    } elseif (!hash_equals($state['token'], $receivedToken)) {
        $audit[] = ['① token 校验', substr($receivedToken, 0, 16) . '…', '✗ 与当前 token 不一致，拒绝'];
        $error = '请求被拒绝：CSRF token 不匹配。';
    } else {
        $audit[] = ['① token 校验', substr($receivedToken, 0, 16) . '…', '✓ 匹配'];
    }

    // ------------------------------------------------------------------
    // 层 ③：Referer / Origin 作为额外信号
    //
    // 注意它在 token 之后的**补充**位置 —— 就算这一层被绕过（比如攻击者
    // 去掉了 Referer），上面那层 token 校验依然会拦住请求。
    //
    // 反过来不成立：只有 Referer 校验（medium 档）是守不住的。
    // ------------------------------------------------------------------
    if ($error === '') {
        if ($referer !== '' && strpos($referer, $host) === false) {
            $audit[] = ['③ Referer 检查', $referer, '✗ 来源可疑，拒绝'];
            $error = '请求被拒绝：Referer 与本站不符。';
        } elseif ($referer === '') {
            $audit[] = ['③ Referer 检查', '（未提供）', '— 跳过（不单独作为拒绝依据）'];
        } else {
            $audit[] = ['③ Referer 检查', $referer, '✓ 通过'];
        }
    }

    // ------------------------------------------------------------------
    // 层 ④：业务上还应该做二次确认
    //
    // 改邮箱这类操作，真实项目里应当要求输入原密码、或者给旧邮箱发确认信。
    // 这样即使 CSRF 拿到了请求，也改不成。
    // 本档只在页面上说明这一点，不实现完整的确认流程（那属于业务逻辑）。
    // ------------------------------------------------------------------

    if ($error === '' && $receivedEmail !== '') {
        $state['email'] = $receivedEmail;
        csrf_save($state);
        $changed = true;

        // 层 ②：用过即换
        $state = csrf_rotate_token($state);
        $audit[] = ['② 一次性 token', '已轮换为新值', '✓ 旧 token 作废'];
    }
}
?>
<?php layout_header(
    'CSRF · 难度 high（已修复）',
    'token 之所以有效，是因为它放在了一个攻击者读不到的地方。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护</h3>
  <pre style="margin:10px 0 0;background:#064e3b"><span class="c">// ① token 校验（会话绑定 + 定长比较）</span>
<span class="k">if</span> (!<span class="v">hash_equals</span>($state[<span class="s">'token'</span>], $receivedToken)) { <span class="c">/* 拒绝 */</span> }

<span class="c">// ② 用过即换</span>
$state = csrf_rotate_token($state);

<span class="c">// ③ Referer 只作为「额外信号」，不单独承担防线</span>
<span class="k">if</span> ($referer !== <span class="s">''</span> &amp;&amp; <span class="v">strpos</span>($referer, $host) === <span class="f">false</span>) { <span class="c">/* 拒绝 */</span> }</pre>
  <p style="margin:10px 0 0;font-size:14px;color:#065f46">
    <b>关键是 ① 的位置：token 只通过本站页面渲染出来，攻击者的页面读不到它。</b><br>
    注意 token 必须在<b>请求体</b>里提交 —— 如果放 Cookie 里，浏览器会自动带上，
    攻击者发起的请求也会自动带上，那就完全失效了。
  </p>
</div>

<?php render_csrf_state($state, '这个 token 只在本站页面里渲染 —— 攻击者的页面读不到它。'); ?>

<div class="card">
  <h3 style="margin-top:0">正常功能的表单（注意那个隐藏字段）</h3>
  <form method="post" action="high.php">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($state['token']) ?>">
    <div class="row">
      <label style="min-width:90px">绑定邮箱</label>
      <input type="text" name="email" style="flex:1;font-family:var(--mono)"
             value="<?= htmlspecialchars($state['email']) ?>">
    </div>
    <div class="row">
      <button type="submit">保存</button>
      <a href="?reset=1" style="margin-left:10px;font-size:13px">重置场景</a>
    </div>
  </form>
  <p class="hint" style="margin:10px 0 0">
    把 low / medium 档成功的那种请求原样发过来（不带 token）—— 会被层 ① 拒绝。
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
    <p class="hint" style="margin:10px 0 0">
      上一次请求：<b><?= $changed ? '已修改' : '被拒绝' ?></b>
      <?php if ($error !== ''): ?>
        —— <?= htmlspecialchars($error) ?>
      <?php endif; ?>
    </p>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">攻击载荷对照（都被挡住）</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:30%">载荷</th><th>结果</th></tr></thead>
      <tbody>
        <tr>
          <td style="font-size:13px">不带 token 的跨站 POST</td>
          <td style="font-size:13px;color:var(--muted)">层 ① 拒绝（缺少 token）</td>
        </tr>
        <tr>
          <td style="font-size:13px">带一个随便编的 token</td>
          <td style="font-size:13px;color:var(--muted)">层 ① 拒绝（不匹配）</td>
        </tr>
        <tr>
          <td style="font-size:13px">带「上一次」的 token（重放）</td>
          <td style="font-size:13px;color:var(--muted)">层 ① 拒绝（已轮换，旧值作废）</td>
        </tr>
        <tr>
          <td style="font-size:13px">去掉 Referer 再试</td>
          <td style="font-size:13px;color:var(--muted)">层 ③ 跳过，但层 ① 依然拦住 —— <b>这正是分层的作用</b></td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<div class="card">
  <h3 style="margin-top:0">修复要点总结</h3>
  <ol style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>用 token，而且必须是「攻击者读不到」的 token</b> ——
      放在本站页面里、通过请求体提交。**不要放在 Cookie 里**
      （自动携带 = 白送）
    </li>
    <li>
      <b>token 要绑定会话</b> —— 否则攻击者可以拿自己的 token 去骗别人
    </li>
    <li>
      <b>用 <code>hash_equals()</code> 比较</b> —— 同样的理由，避免时序侧信道
    </li>
    <li>
      <b>做过即换（可选但推荐）</b> —— 顺带挡住重放
    </li>
    <li>
      <b>Referer / Origin 只能当补充</b> ——
      它们是「客户端自愿提供」的信息，不能单独承担防线
    </li>
    <li>
      <b>敏感操作加二次确认</b> —— 改邮箱、改密码、转账这类操作，
      要求原密码或邮件确认。这样即使 CSRF 成立也改不成
    </li>
    <li>
      <b>别用 GET 做状态变更</b> ——
      `&lt;img src="/change_email?to=..."&gt;` 这种攻击连表单都不需要，
      一个图片标签就够了
    </li>
    <li>
      <b>给会话 Cookie 加 <code>SameSite=Lax</code>（或 Strict）</b> ——
      现代浏览器会阻止跨站请求携带 Cookie。
      这是**浏览器层面的兜底**，但它是纵深防御的一层，不是替代品
      （老浏览器、以及某些场景下 Lax 仍允许顶级导航携带 Cookie）
    </li>
  </ol>
  <p class="hint">
    最容易踩的一条：<b>「我检查了 Referer，所以不会被 CSRF」。</b><br>
    medium 档就是为了说明这件事 —— 攻击者可以<u>选择不发 Referer</u>，
    也可以让<u>自己域名的名字里包含目标域名</u>。
    这两条都不需要任何「技术手段」，后者甚至只要买一个域名。
  </p>
</div>

<?php layout_footer(); ?>
