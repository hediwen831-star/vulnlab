<?php
/**
 * PHP 反序列化 · high 档 —— 修复对照
 *
 * 修复方式：**用 `allowed_classes` 限制能被实例化的类**。
 *
 * ══════════════════════════════════════════════════════════════════
 * 为什么这是唯一可靠的修复
 * ══════════════════════════════════════════════════════════════════
 *
 * 前两档的失败模式：
 *
 *   low    ：完全放开 —— 任意类、任意属性
 *   medium ：类名黑名单 —— 而黑名单有两个结构性问题：
 *
 *     ① **绕过的写法是无穷的**：大小写、`C:` 格式、`O:+5:` 前导加号……
 *     ② **它会在你加新类时过期**：今天只有三个类能形成 POP 链，
 *        明天有人加了个带 `__destruct` 的类，黑名单就漏了 ——
 *        而且**没有任何机制会提醒你更新它**
 *
 * 而 `allowed_classes` 换了一个方向：
 *
 *   **不问「哪些类是危险的」，而是问「哪些类是这里真的需要的」。**
 *
 * 分页组件只应该反序列化分页相关的类，那就只允许那一个。
 * 其余的一律拒绝 —— **不需要关心它们危险不危险。**
 *
 * 这又回到了整个靶场反复出现的那个原则：
 * **白名单，而不是黑名单。**
 *
 * ══════════════════════════════════════════════════════════════════
 * 被拒绝的类会发生什么
 * ══════════════════════════════════════════════════════════════════
 *
 * 不在白名单里的类会被实例化成 `__PHP_Incomplete_Class` ——
 * 一个"空壳"：它存在、属性也在，但**方法不可用，魔术方法也不会触发**。
 *
 * 所以 POP 链从根上断了：链的每个节点都需要真实类的方法才能传递下去。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/classes.php';
require __DIR__ . '/../lib/paths.php';   // 用于把「$dir 该写什么」显示到页面上

const TARGET_DIR = __DIR__ . '/../uploads';

$data = isset($_POST['data']) ? (string) $_POST['data'] : '';
$submitted = ($data !== '');

$dump = '';
$error = '';
$audit = [];
$newFiles = [];
$incompleteClasses = [];

if ($submitted) {
    if (!is_dir(TARGET_DIR)) {
        @mkdir(TARGET_DIR, 0777, true);
    }
    $beforeFiles = array_diff(scandir(TARGET_DIR) ?: [], ['.', '..']);

    // ------------------------------------------------------------------
    // 修复点：allowed_classes 白名单
    //
    // 这里只允许 SafeNote —— 一个没有危险方法的类。
    // 其余类即使出现在序列化字符串里，也只会变成 __PHP_Incomplete_Class。
    //
    // 注：如果完全不需要反序列化对象，用 allowed_classes => false 更彻底。
    // ------------------------------------------------------------------
    $allowed = ['SafeNote'];
    $audit[] = ['① 类白名单', implode(', ', $allowed), '✓ 只有这个类能被实例化'];

    try {
        $obj = @unserialize($data, ['allowed_classes' => $allowed]);

        if ($obj === false && $data !== 'b:0;') {
            $error = '反序列化失败：字符串格式不合法。';
        } else {
            $dump = print_r($obj, true);

            // 收集被拒绝的类（变成 __PHP_Incomplete_Class 的）
            $incompleteClasses = _find_incomplete($obj);
            if ($incompleteClasses) {
                $audit[] = [
                    '② 拒绝的类',
                    implode(', ', array_unique($incompleteClasses)),
                    '✗ 已降级为 __PHP_Incomplete_Class（方法不可用）',
                ];
            } else {
                $audit[] = ['② 拒绝的类', '（无）', '—'];
            }

            // 显式销毁对象，让 __destruct 立即执行 ——
            // 否则副作用检查看不到变化。（详见 low.php 的说明）
            //
            // 本档这么做还有一层意义：白名单让对象降级成 __PHP_Incomplete_Class，
            // 它的析构方法根本不存在 —— 所以"销毁"这一步不会有任何副作用，
            // 恰好从反面印证了「链在第一个节点就断了」。
            unset($obj);

            $afterFiles = array_diff(scandir(TARGET_DIR) ?: [], ['.', '..']);
            $newFiles = array_values(array_diff($afterFiles, $beforeFiles));
            $audit[] = [
                '③ 副作用检查',
                $newFiles ? implode(', ', $newFiles) : '无新文件',
                $newFiles ? '✗ 有文件被写出（不该发生）' : '✓ 无副作用',
            ];
        }
    } catch (Throwable $e) {
        $error = '反序列化时抛出异常：' . $e->getMessage();
    }
}

/**
 * 递归找出对象图里的 `__PHP_Incomplete_Class` 实例。
 *
 * 这个类名本身就说明了问题：**它不是一个真正的类，只是一个残骸**。
 * PHP 用这种方式告诉你「这个类不在允许列表里，我保留属性但不会给你方法」。
 */
function _find_incomplete(mixed $value, int $depth = 0): array
{
    if ($depth > 8) {
        return [];
    }

    $found = [];

    if (is_object($value)) {
        if ($value instanceof __PHP_Incomplete_Class) {
            $className = (array) $value;
            $found[] = (string) ($className['__PHP_Incomplete_Class_Name'] ?? '?');
        }
        foreach ((array) $value as $item) {
            $found = array_merge($found, _find_incomplete($item, $depth + 1));
        }
    } elseif (is_array($value)) {
        foreach ($value as $item) {
            $found = array_merge($found, _find_incomplete($item, $depth + 1));
        }
    }

    return $found;
}

/** 攻击载荷对照 */
$attacks = [
    'O:5:"cache":3:{s:3:"key";s:9:"shell.php";s:5:"value";s:20:"<?php echo 1; ?>";s:5:"store";O:9:"filestore":1:{s:3:"dir";s:14:"../uploads/";}}'
        => 'low 档的完整 POP 链（大小写变形）',
    'O:5:"Cache":3:{s:3:"key";s:9:"shell.php";s:5:"value";s:20:"<?php echo 1; ?>";s:5:"store";O:9:"FileStore":1:{s:3:"dir";s:14:"../uploads/";}}'
        => '标准写法',
    'O:8:"SafeNote":1:{s:4:"text";s:5:"hello";}'
        => '白名单内的类（对照组）',
];
?>
<?php layout_header(
    'PHP 反序列化 · 难度 high（已修复）',
    'allowed_classes 白名单 —— 不问"哪些类是危险的"，只问"这里需要哪些类"。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护</h3>
  <pre style="margin:10px 0 0;background:#064e3b">$obj = unserialize($data, [<span class="s">'allowed_classes'</span> =&gt; [<span class="s">'SafeNote'</span>]]);</pre>
  <p style="margin:10px 0 0;font-size:14px;color:#065f46">
    只有 <code>SafeNote</code> 能被实例化。其余类降级为
    <code>__PHP_Incomplete_Class</code> —— 空壳，方法不可用，魔术方法不触发。
    <b>POP 链从根上断了。</b>
  </p>
</div>

<div class="card">
  <form method="post" action="high.php">
    <div class="row">
      <textarea name="data" rows="4" style="flex:1;font-family:var(--mono);font-size:13px"
                placeholder='O:5:"cache":3:{...}'
      ><?= htmlspecialchars($data) ?></textarea>
    </div>
    <div class="row">
      <button type="submit">反序列化</button>
    </div>
  </form>
  <p class="hint">把 low / medium 档成功的 payload 原样粘进来试试。</p>
  <?php render_target_dir_hint(TARGET_DIR); ?>
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
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
    </div>
  <?php endif; ?>

  <?php if ($dump !== ''): ?>
    <?php render_code_board('反序列化得到的对象结构（注意 __PHP_Incomplete_Class）', trim($dump)); ?>
  <?php endif; ?>

  <div class="card" style="<?= $newFiles ? 'border-color:#fecaca;background:var(--danger-soft)' : 'border-color:#a7f3d0;background:var(--ok-soft)' ?>">
    <h3 style="margin-top:0">副作用检查</h3>
    <?php if ($newFiles): ?>
      <b style="color:var(--danger)">★ 严重：有文件被写出 —— 修复已失效！</b>
      <div class="mono" style="margin-top:8px"><?= htmlspecialchars(implode(', ', $newFiles)) ?></div>
    <?php else: ?>
      <b style="color:var(--ok)">✓ 无文件写出，POP 链未能形成</b>
      <?php if ($incompleteClasses): ?>
        <p style="margin:8px 0 0;font-size:14px;color:#065f46">
          你的 payload 里这些类被拒绝了：
          <code><?= htmlspecialchars(implode(', ', array_unique($incompleteClasses))) ?></code>
          —— 它们变成了空壳，<code>__destruct</code> 不会执行。
        </p>
      <?php endif; ?>
    <?php endif; ?>
  </div>
<?php endif; ?>

<h2>对照实验：同一批 payload，三档的结果</h2>
<div class="tbl-wrap">
  <table>
    <thead><tr>
      <th style="width:52%">载荷</th>
      <th style="width:24%">说明</th>
      <th>high 档结果</th>
    </tr></thead>
    <tbody>
      <?php foreach ($attacks as $payload => $note): ?>
        <tr>
          <td class="mono" style="word-break:break-all;font-size:12px"><?= htmlspecialchars($payload) ?></td>
          <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          <td>
            <?php if (strpos($payload, 'SafeNote') !== false): ?>
              <span class="tag" style="background:var(--ok-soft);color:var(--ok)">正常实例化</span>
            <?php else: ?>
              <span class="tag high">类被拒绝</span>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="card" style="margin-top:20px">
  <h3 style="margin-top:0">为什么黑名单在这里必然失败</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    medium 档的黑名单有两个结构性问题，都不是"写得不够认真"能解决的：
  </p>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:26%">问题</th><th>说明</th></tr></thead>
      <tbody>
        <tr>
          <td><b>绕过写法无穷</b></td>
          <td>
            大小写（<code>cache</code>）、<code>C:</code> 自定义序列化格式、
            <code>O:+5:</code> 前导加号、Unicode 转义……
            字符串匹配永远追不上语法变体
          </td>
        </tr>
        <tr>
          <td><b>会随代码演进过期</b></td>
          <td>
            今天只有 3 个类能形成链，明天有人加了个带 <code>__destruct</code> 的类 ——
            黑名单漏了，而<b>没有任何机制提醒你更新它</b>。
            这类"沉默的失效"比一次明显的报错危险得多
          </td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="hint">
    而白名单不需要关心"危险列表"是否完整 —— 它只回答一个问题：
    <b>这个位置真的需要反序列化哪些类？</b>
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">修复要点总结</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>首选：不用 `unserialize`。</b>
      前后端之间传数据用 JSON —— 它不会构造对象，也就没有 POP 链这一说。
      这是最彻底的修复（消除调用就消除了攻击面）。
    </li>
    <li>
      <b>必须用 `unserialize` 时，一律带 `allowed_classes`。</b>
      不需要对象就写 <code>false</code>，需要就精确列出类名。
    </li>
    <li>
      <b>不要用黑名单过滤类名。</b>
      绕过写法无穷 + 会随代码演进过期 —— 两个问题都不是"更仔细"能解决的。
    </li>
    <li>
      <b>审查所有魔术方法。</b>
      <code>__destruct</code> / <code>__wakeup</code> / <code>__toString</code> /
      <code>__call</code> —— 只要它们会拿属性去做危险操作，这个类就是 POP 链的候选节点。
    </li>
    <li>
      <b>签名 / 加密序列化数据。</b>
      如果数据来自客户端，用 HMAC 校验后再反序列化 ——
      攻击者无法构造出合法签名，也就无法控制对象。
    </li>
    <li>
      <b>注意 `phar://` 这个隐藏入口。</b>
      即使代码里没有 <code>unserialize</code>，用 <code>phar://</code> 包装器
      访问一个 `.phar` 文件也会**隐式触发反序列化** ——
      所以这个场景和「文件包含」是联动的（见 writeups/lfi.md）。
    </li>
  </ul>
</div>

<?php layout_footer(); ?>
