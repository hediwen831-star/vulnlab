<?php
/**
 * CSRF 场景的共享状态 —— 三档共用。
 *
 * ══════════════════════════════════════════════════════════════════
 * 为什么用文件存状态，而不是 $_SESSION
 * ══════════════════════════════════════════════════════════════════
 *
 * 「已登录用户」这件事，真实项目里由会话（session）承载。
 * 靶场本来也可以用 `$_SESSION`，但那会带来两个与教学无关的麻烦：
 *
 *   · 使用者必须先用浏览器打开页面拿到 Cookie，才能用 curl / Burp 复现
 *   · CI 里要维护 cookie 罐，测试代码会变复杂
 *
 * 所以这里用一个 JSON 文件存「当前登录用户的资料 + 当前 token」，
 * 相当于**一个所有请求共享的单一会话**。
 *
 * ⚠️ 这个简化**不影响本场景想演示的东西**：防 CSRF 的核心性质是
 *    「攻击者的页面读不到目标站点的凭据」。只要 token 存在服务器端、
 *    不随 cookie 之外的方式泄露，这个性质就和真实会话下完全一样。
 *    三档的差异（有没有校验、校验什么）也没有被简化掉。
 *
 * 状态文件放在 html/data/ 下 —— 和 SQL 场景的 SQLite 库同一个目录。
 */

declare(strict_types=1);

/** 状态文件路径 */
function csrf_state_path(): string
{
    return __DIR__ . '/../data/csrf_state.json';
}

/** 演示里「攻击者想改成的邮箱」—— 达成即通关 */
const CSRF_ATTACKER_EMAIL = 'attacker@evil.example';

/** 通关凭证 */
const CSRF_FLAG = 'VULNLAB{csrf_token_forgotten}';

/**
 * 读取当前状态；文件不存在时初始化。
 *
 * @return array{email:string, token:string}
 */
function csrf_load(): array
{
    $path = csrf_state_path();

    if (!is_file($path)) {
        return csrf_reset();
    }

    $raw = @file_get_contents($path);
    $data = $raw === false ? null : json_decode($raw, true);

    if (!is_array($data) || !isset($data['email'], $data['token'])) {
        return csrf_reset();
    }

    return ['email' => (string) $data['email'], 'token' => (string) $data['token']];
}

/**
 * 重置状态 —— 回到「受害者还没被改邮箱」的初始样子，并换一个新 token。
 *
 * 页面上有「重置场景」的入口。为什么要它：
 * CSRF 攻击一旦成功，状态就变了；使用者想再试一遍就得先把场景恢复，
 * 否则会分不清「这次没成功」和「上次已经改过了」。
 *
 * @return array{email:string, token:string}
 */
function csrf_reset(): array
{
    $state = [
        'email' => 'alice@vulnlab.local',
        'token' => bin2hex(random_bytes(16)),
    ];

    $dir = dirname(csrf_state_path());
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    @file_put_contents(csrf_state_path(), json_encode($state, JSON_UNESCAPED_SLASHES), LOCK_EX);

    return $state;
}

/** 写回状态 */
function csrf_save(array $state): void
{
    @file_put_contents(
        csrf_state_path(),
        json_encode($state, JSON_UNESCAPED_SLASHES),
        LOCK_EX
    );
}

/**
 * 换一个新 token（只在成功修改之后调用）。
 *
 * 这是「一次性 token」的实现方式：用过一次就作废。
 * 注意它并不是防 CSRF 的必需品（不轮换的 token 同样能挡住跨站请求），
 * 但它能顺带挡住「重放同一个请求」。
 *
 * @return array{email:string, token:string}
 */
function csrf_rotate_token(array $state): array
{
    $state['token'] = bin2hex(random_bytes(16));
    csrf_save($state);
    return $state;
}

/**
 * 判断是否已经达成目标（邮箱被改成了攻击者想要的值）。
 */
function csrf_goal_reached(array $state): bool
{
    return strcasecmp($state['email'], CSRF_ATTACKER_EMAIL) === 0;
}

/**
 * 渲染「当前状态」卡片，三档共用。
 *
 * 把邮箱(token 不显示)直接摆出来 —— 使用者才能立刻看到
 * 「我这次的请求到底有没有生效」，而不用靠猜。
 */
function render_csrf_state(array $state, string $extraNote = ''): void
{
    $reached = csrf_goal_reached($state);
    ?>
    <div class="card" style="<?= $reached ? 'border-color:#fecaca;background:var(--danger-soft)' : '' ?>">
      <h3 style="margin-top:0">当前状态</h3>
      <div class="kv">
        <b>登录用户</b><span class="mono">alice</span>
      </div>
      <div class="kv">
        <b>绑定邮箱</b><span class="mono"><?= htmlspecialchars($state['email']) ?></span>
      </div>
      <div class="kv">
        <b>服务端持有的 token</b>
        <span class="mono" style="word-break:break-all;font-size:12px">
          <?= htmlspecialchars(substr($state['token'], 0, 16)) ?>…
        </span>
      </div>
      <?php if ($reached): ?>
        <p style="margin:14px 0 0;color:var(--danger);font-weight:500">
          ★ 受害者的邮箱已经被改成了 <?= htmlspecialchars(CSRF_ATTACKER_EMAIL) ?> —— 通关凭证：
        </p>
        <pre style="margin:6px 0 0"><?= htmlspecialchars(CSRF_FLAG) ?></pre>
      <?php endif; ?>
      <?php if ($extraNote !== ''): ?>
        <p class="hint" style="margin:12px 0 0"><?= $extraNote ?></p>
      <?php endif; ?>
    </div>
    <?php
}
