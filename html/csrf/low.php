<?php
/**
 * CSRF · low 档 —— 修改绑定邮箱，零防护
 *
 * 漏洞成因：状态变更接口**不验证请求是不是本站发起的**。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * CSRF 和前七个场景的根本区别：**它的攻击目标不是服务器，而是浏览器**
 * ══════════════════════════════════════════════════════════════════
 *
 * 前面所有场景（SQL / 命令注入 / 文件包含 / 反序列化 / XXE / JWT）里，
 * 攻击者都是**直接向服务器发请求**，服务器是受害者。
 *
 * CSRF 不一样：
 *
 *   · 攻击者**不需要**能访问目标服务器
 *   · 攻击者**读不到**任何响应内容（同源策略挡着）
 *   · 攻击者做的只有一件事：**让受害者的浏览器替他发一个请求**
 *
 * 而这个请求会**自动带上受害者的登录凭据**（Cookie）——
 * 因为浏览器认为「这是发往那个站点的请求，那就该带上那个站点的 Cookie」。
 *
 * 于是服务器看到的是：
 *
 *     一个带着合法 Cookie 的、看起来完全正常的请求
 *
 * 它无法从请求本身判断出「这是用户自己点的，还是被别的页面骗着发的」。
 *
 * ══════════════════════════════════════════════════════════════════
 * 所以防御的关键是：让请求里带上一个「跨站页面拿不到」的东西
 * ══════════════════════════════════════════════════════════════════
 *
 * 攻击者的页面能：
 *   ✅ 让浏览器发出任意请求（表单 / img / fetch）
 *   ✅ 让请求自动带上 Cookie
 *
 * 攻击者的页面**不能**：
 *   ❌ 读取目标站点的响应（同源策略）
 *   ❌ 读取目标站点页面里的内容
 *
 * 所以只要在表单里放一个**只有目标站点的页面才知道的随机值**，
 * 攻击者就填不出来 —— 这是所有 CSRF 防护的基础。
 *
 * 本档什么都没放。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/state.php';

// 重置场景（方便反复实验）
if (isset($_GET['reset'])) {
    csrf_reset();
    header('Location: ' . basename(__FILE__));
    exit;
}

$state = csrf_load();
$submitted = false;
$changed = false;
$receivedEmail = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submitted = true;
    $receivedEmail = isset($_POST['email']) ? trim((string) $_POST['email']) : '';

    if ($receivedEmail !== '') {
        // ------------------------------------------------------------------
        // 漏洞点：就这么改了
        //
        // 没有 token、没有 Referer 检查、没有 Origin 检查 ——
        // 也没有任何「这个请求是不是从本站页面发出来的」的判断。
        //
        // 只要请求带上受害者的 Cookie，服务器就照做。
        // 而「让浏览器发出这个请求」，攻击者有一堆办法做到。
        // ------------------------------------------------------------------
        $state['email'] = $receivedEmail;
        csrf_save($state);
        $changed = true;
    }
}

$referer = (string) ($_SERVER['HTTP_REFERER'] ?? '');
?>
<?php layout_header(
    'CSRF · 难度 low',
    '状态变更接口不验证请求来源 —— 攻击者的页面可以让浏览器替他发请求。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    CSRF 的后果取决于被攻击的接口 —— 改邮箱通常意味着<b>接着就能走「忘记密码」接管账号</b>。
    本靶场只演示「改邮箱」这一步，请勿构造攻击真实站点的页面。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$state[<span class="s">'email'</span>] = $_POST[<span class="s">'email'</span>];
csrf_save($state);
<span class="c">// 就这些。没有 token、没有 Referer 检查、没有 Origin 检查。</span></pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    让 <code>alice</code> 的绑定邮箱变成 <code><?= htmlspecialchars(CSRF_ATTACKER_EMAIL) ?></code>。
  </p>
  <p class="hint" style="margin:8px 0 0">
    ⚠️ 注意要求：**你不能直接在这个页面的表单里填那个邮箱然后提交** ——
    那叫「用户自己改的」，不是 CSRF。<br>
    要做的是：构造一个页面，让<b>受害者的浏览器</b>替他发出这个请求。
    本目录下的 <code>attacker.html</code> 就是一个示例攻击页。
  </p>
</div>

<?php render_csrf_state($state, $referer !== ''
    ? '上一次请求带的 Referer：<code>' . htmlspecialchars($referer) . '</code>'
    : '上一次请求没有带 Referer。'); ?>

<div class="card">
  <h3 style="margin-top:0">正常功能的表单（受害者角度的页面）</h3>
  <form method="post" action="low.php">
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
  <?php if ($submitted): ?>
    <p class="hint" style="margin:10px 0 0">
      上一次请求：<b><?= $changed ? '已修改' : '未修改' ?></b>
      （收到的邮箱值：<code><?= htmlspecialchars($receivedEmail) ?></code>）
    </p>
  <?php endif; ?>
</div>

<div class="card">
  <h3 style="margin-top:0">攻击页面长什么样</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    本目录下的 <code>attacker.html</code> 就是攻击者页面。把它当作
    <b>部署在攻击者域名下</b>的页面来看待 —— 靶场为了自包含只能把它放在同一个域里，
    但这不影响结论：
  </p>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>浏览器提交表单时**只看 action 指向哪里**，不关心页面本身来自哪里</li>
    <li>请求发往靶站时，会**自动带上靶站的 Cookie**</li>
    <li>靶站无法从请求本身分辨「这是用户自己点的还是被骗着发的」</li>
  </ul>
  <p class="hint">
    用 curl 直接发一个带外部 Referer 的 POST，等价于浏览器提交表单 ——
    这是验证 CSRF 最省事的办法：
    <br>
    <code>curl -X POST http://127.0.0.1:8080/csrf/low.php -H "Referer: http://evil.example/" -d "email=attacker@evil.example"</code>
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>这个接口判断「请求该不该被接受」时，看了哪些东西？（答案：只看了 POST 里的字段）</li>
    <li>浏览器发请求时，会自动附加哪些「请求方控制不了」的东西？</li>
    <li>攻击者的页面能不能读到这个站点的响应内容？为什么不能？</li>
    <li>能不能在表单里放一个值，让它**只有本站页面才会知道**？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/csrf.md</code>。</p>
</div>

<?php layout_footer(); ?>
