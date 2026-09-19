<?php
/**
 * PHP 反序列化 · medium 档
 *
 * 漏洞成因：用**类名黑名单**过滤序列化字符串。
 *
 * 这里的绕过点是一个 PHP 的语言特性：
 *
 *   **类名在 PHP 里是不区分大小写的。**
 *
 *   你写 `O:5:"cache":3:{...}`，PHP 一样会去实例化 `Cache` 类 ——
 *   但黑名单里检查的是 `strpos($data, 'Cache')`，小写的 `cache` 匹配不上。
 *
 * 这和 SQL 注入里的「大小写绕过」（`SeLeCt`）、命令注入里的
 * 「换一种写法表示同一个东西」是同一类问题：
 *
 *   **过滤器假设「危险的东西只有一种写法」，而语言本身提供了多种等价写法。**
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
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
$newFiles = [];
$blockedBy = '';

if ($submitted) {
    if (!is_dir(TARGET_DIR)) {
        @mkdir(TARGET_DIR, 0777, true);
    }
    $beforeFiles = array_diff(scandir(TARGET_DIR) ?: [], ['.', '..']);

    // ------------------------------------------------------------------
    // 漏洞点：黑名单检查类名 + 区分大小写
    //
    // 两个独立的问题叠加：
    //   ① 用黑名单枚举"危险类" —— 而危险与否取决于有哪些魔术方法，
    //      加一个类就得记得更新黑名单（迟早会忘）
    //   ② strpos 区分大小写，而 PHP 的类名不区分 —— 小写写法能绕过
    // ------------------------------------------------------------------
    $blacklist = ['FileStore', 'Cache', 'Logger'];

    foreach ($blacklist as $bad) {
        if (strpos($data, $bad) !== false) {
            $blockedBy = $bad;
            break;
        }
    }

    if ($blockedBy !== '') {
        $error = '输入被拦截：包含被禁止的类名「' . $blockedBy . '」。';
    } else {
        try {
            $obj = @unserialize($data);
            if ($obj === false && $data !== 'b:0;') {
                $error = '反序列化失败：字符串格式不合法（或包含未定义的类）。';
            } else {
                $dump = print_r($obj, true);

                // 显式销毁对象，让 __destruct 立即执行 ——
                // 否则它要等到脚本结束才跑，那时候响应已经组装完，
                // 下面的副作用检查就看不到任何变化了。（详见 low.php 的说明）
                unset($obj);

                $afterFiles = array_diff(scandir(TARGET_DIR) ?: [], ['.', '..']);
                $newFiles = array_values(array_diff($afterFiles, $beforeFiles));
            }
        } catch (Throwable $e) {
            $error = '反序列化时抛出异常：' . $e->getMessage();
        }
    }
}

/** 绕过示例 */
$bypasses = [
    'O:5:"cache":3:{...}'   => '★ 类名小写 —— PHP 不区分大小写，但 strpos 区分',
    'O:9:"filestore":1:{...}' => '★ 同理：filestore 能实例化 FileStore',
    'O:5:"Cache":3:{...}'   => '对照组：会被黑名单拦下',
    'O:5:"LOGger":...'      => '★ 混合大小写也可以',
];
?>
<?php layout_header(
    'PHP 反序列化 · 难度 medium',
    '类名黑名单 —— 而 PHP 的类名是不区分大小写的。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$blacklist = [<span class="s">'FileStore'</span>, <span class="s">'Cache'</span>, <span class="s">'Logger'</span>];

foreach ($blacklist as $bad) {
    if (<span class="v">strpos</span>($data, $bad) !== false) { <span class="c">/* 拦截 */</span> }
}

$obj = unserialize($data);   <span class="c">// 这里没有任何类限制</span></pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    和 low 档一样写出一个文件，但这次不能直接写 `Cache` / `FileStore` 这些**大写**类名。
  </p>
  <?php render_target_dir_hint(TARGET_DIR); ?>
</div>

<div class="card">
  <form method="post" action="medium.php">
    <div class="row">
      <textarea name="data" rows="4" style="flex:1;font-family:var(--mono);font-size:13px"
                placeholder='O:5:"cache":3:{...}'
      ><?= htmlspecialchars($data) ?></textarea>
    </div>
    <div class="row">
      <button type="submit">反序列化</button>
    </div>
  </form>
</div>

<?php if ($blockedBy !== ''): ?>
  <div class="card tight" style="background:var(--warn-soft);border-color:#fde68a;margin-bottom:14px">
    <div style="font-size:13px;color:#92400e;margin-bottom:8px">过滤器命中</div>
    <div class="kv"><b>命中的词</b><span class="mono"><?= htmlspecialchars($blockedBy) ?></span></div>
    <p style="margin:8px 0 0;font-size:13px;color:#92400e">
      它检查的是你输入里<b>有没有这几个大写字符串</b>，
      而不是<b>PHP 会实例化哪个类</b> —— 这两者的差集就是绕过的空间。
    </p>
  </div>
<?php endif; ?>

<?php if ($error !== '' && $blockedBy === ''): ?>
  <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
    <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
  </div>
<?php endif; ?>

<?php if ($dump !== ''): ?>
  <?php render_code_board('反序列化得到的对象结构', trim($dump)); ?>
  <div class="card" style="<?= $newFiles ? 'border-color:#a7f3d0;background:var(--ok-soft)' : '' ?>">
    <h3 style="margin-top:0">副作用检查</h3>
    <?php if ($newFiles): ?>
      <p style="margin:0;color:var(--ok);font-weight:500">
        ★ 产生了 <?= count($newFiles) ?> 个新文件：
        <span class="mono"><?= htmlspecialchars(implode(', ', $newFiles)) ?></span>
      </p>
    <?php else: ?>
      <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
        本次没有新文件 —— 可能是链没打通，也可能是<b>覆盖了同名文件</b>
        （覆盖不会产生"新"文件）。换个文件名再试一次即可区分。
      </p>
      <?php render_file_list_note(array_values(array_diff(scandir(TARGET_DIR) ?: [], ['.', '..']))); ?>
    <?php endif; ?>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">核心绕过点</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:34%">你的输入</th><th style="width:30%">黑名单看到的</th><th>PHP 实际实例化的类</th></tr></thead>
      <tbody>
        <tr>
          <td class="mono">O:5:"<b>Cache</b>":3:{...}</td>
          <td style="color:var(--danger)">命中 → 拦截</td>
          <td>—</td>
        </tr>
        <tr>
          <td class="mono">O:5:"<b>cache</b>":3:{...}</td>
          <td style="color:var(--ok)">不命中 → 放行</td>
          <td><b>Cache</b>（同一个类）</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="hint">
    <b>PHP 的类名、函数名、关键字都不区分大小写</b> ——
    而字符串匹配区分。这个不一致制造了一个稳定的绕过点。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">可用载荷</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:56%">写法</th><th>说明</th></tr></thead>
      <tbody>
        <?php foreach ($bypasses as $payload => $note): ?>
          <tr>
            <td class="mono" style="word-break:break-all"><?= htmlspecialchars($payload) ?></td>
            <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <p class="hint">完整 payload 需要你自己补全属性部分 —— 见 writeups/unserialize.md 的推导。</p>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>过滤器检查的是**字符串**，而反序列化解析的是**类名** —— 这两者总是一致吗？</li>
    <li>PHP 里类名区分大小写吗？如果不区分，那有多少种写法能指向同一个类？</li>
    <li>就算把大小写也堵了，黑名单还剩什么弱点？（提示：新增一个类会怎样）</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/unserialize.md</code>。</p>
</div>

<?php layout_footer(); ?>
