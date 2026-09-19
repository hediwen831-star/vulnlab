<?php
/**
 * SSTI · low 档 —— 直接把模板表达式交给 eval
 *
 * 漏洞成因：自研模板引擎用 `eval('return ' . $expr . ';')` 求值。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 业务场景：一个「通知模板」功能
 * ══════════════════════════════════════════════════════════════════
 *
 * 运营需要能自己编辑通知文案，里面可以插入一些动态值，比如：
 *
 *     您好，您的订单金额为 {{ 199 * 2 }} 元，请及时支付。
 *
 * 这个需求看起来完全正当 —— 而且很容易实现：
 * 用正则找到 `{{ }}`，把里面的内容当表达式算出来。
 *
 * ── 问题就出在「当表达式算出来」这一步 ──
 *
 * 「表达式」在 PHP 里是一个极大的概念。开发者心里的「表达式」是：
 *
 *     199 * 2
 *
 * 而 `eval` 理解的「表达式」是：
 *
 *     199 * 2
 *     phpinfo()
 *     file_get_contents('/etc/passwd')
 *     system('whoami')
 *     ...（PHP 有上万个函数，这个列表还在增长）
 *
 * **两者是同一个东西，没有任何语法上的分界。**
 * 你没法用「看起来像不像表达式」把前者和后者分开 ——
 * 因为它们都是合法表达式。
 *
 * ── 所以这不是「过滤没写全」，而是「用错了机制」 ──
 *
 * 前面几个场景（SQL 注入 / 命令注入）里，漏洞来自**拼接** ——
 * 把用户输入拼进了本该是代码的位置。修法是把数据和代码分开。
 *
 * SSTI 是同一件事的另一种形态：**用户输入被当成了代码去执行**。
 * 区别只在于，这里连「拼」这个动作都不需要显式写出来 ——
 * `eval` 一个词就够了。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/template.php';

/** 演示文件（内容是固定标记串） */
const SSTI_PROBE_FILE = 'ssti_probe.txt';

/** 演示用的命令 marker（跨平台：echo 在 cmd 和 sh 上都能用） */
const SSTI_CMD_MARKER = 'VULNLAB_SSTI_CMD_MARKER';

$template = isset($_POST['template']) ? (string) $_POST['template'] : '';
$submitted = ($template !== '');

$rendered = '';
$expressions = [];
$error = '';
$fileRead = false;
$cmdExecuted = false;
$evalError = '';

if ($submitted) {
    $expressions = ssti_find_expressions($template);

    try {
        // ------------------------------------------------------------------
        // 漏洞点：把表达式交给 eval
        //
        // ssti_render 接收一个「怎么求值」的回调 ——
        // 本档传的是 ssti_eval_unsafe()，也就是直接 eval。
        //
        // 注意这行代码本身完全看不出问题：
        // 它只是在「渲染模板」，没有拼接、没有执行命令、没有文件操作。
        // 危险的能力全部藏在 eval 里面。
        // ------------------------------------------------------------------
        $rendered = ssti_render($template, static function (string $expr): string {
            return ssti_eval_unsafe($expr);
        });
    } catch (Throwable $e) {
        $evalError = $e->getMessage();
    }

    $fileRead = strpos($rendered, 'VULNLAB_SSTI_FILE_MARKER') !== false;
    $cmdExecuted = strpos($rendered, SSTI_CMD_MARKER) !== false;
}

/** 正常模板示例 */
$normalTemplate = "您好，您的订单金额为 {{ 199 * 2 }} 元，请及时支付。";
?>
<?php layout_header(
    'SSTI · 难度 low',
    '把用户输入当表达式「求值」，而 PHP 的表达式里包含一切。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    SSTI 一旦成立，通常直接等同于 <b>远程代码执行</b>。<br>
    本靶场只演示读取一个演示文件、以及执行一条无害的 <code>echo</code> 命令，
    请勿构造更有破坏性的载荷。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0"><span class="c">// 找到 {{ 表达式 }} 并求值</span>
$rendered = <span class="v">preg_replace_callback</span>(<span class="s">'/\{\{\s*(.+?)\s*\}\}/s'</span>, function ($m) {
    <span class="k">return</span> <span class="v">eval</span>(<span class="s">'return '</span> . $m[1] . <span class="s">';'</span>);   <span class="c">// ← 这一行</span>
}, $template);</pre>
  <p style="margin:10px 0 0;font-size:14px;color:var(--muted)">
    整个实现只有这几行。它没有拼接、没有执行命令、没有文件操作 ——
    <b>危险的能力全部藏在 <code>eval</code> 里面。</b>
  </p>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    让渲染结果里出现 <code>VULNLAB_SSTI_FILE_MARKER</code>
    （也就是把 <code><?= htmlspecialchars(SSTI_PROBE_FILE) ?></code> 的内容读出来）。
  </p>
  <p class="hint" style="margin:8px 0 0">
    建议分两步走：先用 <code>{{ 7*7 }}</code> 确认「表达式确实被求值了」，
    再想办法把那个文件的内容读出来。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">通知模板</h3>
  <form method="post" action="low.php">
    <div class="row">
      <textarea name="template" rows="5" style="flex:1;font-family:var(--mono);font-size:13px"
                placeholder="您好，您的订单金额为 {{ 199 * 2 }} 元。"
      ><?= htmlspecialchars($template) ?></textarea>
    </div>
    <div class="row">
      <button type="submit">渲染</button>
      <button type="submit" formnovalidate
              onclick="document.querySelector('textarea').value = <?= json_encode($normalTemplate, JSON_UNESCAPED_UNICODE) ?>">
        填入正常模板
      </button>
    </div>
  </form>
</div>

<?php if ($submitted): ?>
  <?php render_ssti_expressions($expressions); ?>

  <?php if ($evalError !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)">求值出错：<?= htmlspecialchars($evalError) ?></b>
    </div>
  <?php endif; ?>

  <div class="card" style="<?= $fileRead || $cmdExecuted ? 'border-color:#fecaca;background:var(--danger-soft)' : '' ?>">
    <h3 style="margin-top:0">渲染结果</h3>
    <pre style="margin:0;white-space:pre-wrap"><?= htmlspecialchars($rendered) ?></pre>

    <?php if ($fileRead): ?>
      <p style="margin:12px 0 0;color:var(--danger);font-weight:500">
        ★ 演示文件的内容出现在了渲染结果里 —— 表达式读到了服务器上的文件
      </p>
    <?php endif; ?>
    <?php if ($cmdExecuted): ?>
      <p style="margin:12px 0 0;color:var(--danger);font-weight:500">
        ★ 系统命令被执行了（输出进了渲染结果）—— 已经等同于 RCE
      </p>
    <?php endif; ?>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li><code>{{ 7*7 }}</code> 会渲染出什么？这说明 <code>{{ }}</code> 里的内容被当成了什么？</li>
    <li>PHP 里「一个表达式」可以包含哪些东西？能不能调用函数？</li>
    <li>如果能调用函数，那么读文件、执行命令的函数能不能调用？</li>
    <li>想一想：<b>有没有一条语法规则能区分「199*2」和「system('id')」？</b>
        （提示：两个都是合法表达式，所以靠语法分不开 —— 这正是修复方向不在「过滤」上的原因）</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/ssti.md</code>。</p>
</div>

<?php layout_footer(); ?>
