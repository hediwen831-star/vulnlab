<?php
/**
 * SSTI · medium 档 —— 黑名单挡住函数调用的括号
 *
 * 防护方式：表达式里不许出现 `(` 和 `)`。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 这个防护的思路是「不允许调用函数」
 * ══════════════════════════════════════════════════════════════════
 *
 * 它其实抓到了一个正确的方向：SSTI 的危害来自**能调用函数**。
 * 而 PHP 里调用函数的写法是 `func(...)` —— 括号是必需的。
 *
 * 于是结论看起来顺理成章：
 *
 *     不许出现括号  ⟹  不许调用函数  ⟹  SSTI 被堵住
 *
 * ── 但这个推理的第二段是错的 ──
 *
 * **PHP 里存在不需要括号就能执行东西的语法。** 最典型的是反引号：
 *
 *     `whoami`
 *
 * 反引号运算符等价于 `shell_exec()` —— 它执行一段 shell 命令，
 * **并返回输出**。整个写法里没有一个括号。
 *
 * 于是绕过就成立了：
 *
 *     {{ `echo VULNLAB_SSTI_CMD_MARKER` }}
 *
 * 表达式里没有 `(` 也没有 `)`，黑名单放行，
 * 而 `eval` 照样把它送进了 shell。
 *
 * ── 这一档和前面几个「黑名单绕过」的共性是 ──
 *
 * 防护者用「某个语法特征」去推断「某个能力」：
 *
 *     有括号   →  在调用函数
 *     `union`  →  在做联合查询
 *     `../`    →  在穿越目录
 *     `Cache`  →  在用那个危险的类
 *
 * 但**语言里表达同一个能力的方式往往不止一种**，
 * 而这些等价写法不会都带同一个特征。
 *
 * 一句话：
 * **黑名单在列「特征」，而特征和「能力」之间永远是多对多的。**
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/template.php';

const SSTI_PROBE_FILE = 'ssti_probe.txt';
const SSTI_CMD_MARKER = 'VULNLAB_SSTI_CMD_MARKER';

$template = isset($_POST['template']) ? (string) $_POST['template'] : '';
$submitted = ($template !== '');

$rendered = '';
$expressions = [];
$blocked = [];
$fileRead = false;
$cmdExecuted = false;
$evalError = '';

if ($submitted) {
    $expressions = ssti_find_expressions($template);

    try {
        $rendered = ssti_render($template, static function (string $expr) use (&$blocked): string {
            // ----------------------------------------------------------
            // 防护：表达式里不许出现括号
            //
            // 思路是「不许调用函数」。这个方向没错，但**手段不够** ——
            // 反引号运算符不需要括号就能执行 shell 命令。
            // ----------------------------------------------------------
            foreach (['(', ')'] as $bad) {
                if (strpos($expr, $bad) !== false) {
                    $blocked[] = [$expr, '包含 ' . $bad];
                    return '[已被过滤]';
                }
            }

            return ssti_eval_unsafe($expr);
        });
    } catch (Throwable $e) {
        $evalError = $e->getMessage();
    }

    $fileRead = strpos($rendered, 'VULNLAB_SSTI_FILE_MARKER') !== false;
    $cmdExecuted = strpos($rendered, SSTI_CMD_MARKER) !== false;
}

$normalTemplate = "您好，您的订单金额为 {{ 199 * 2 }} 元，请及时支付。";
?>
<?php layout_header(
    'SSTI · 难度 medium',
    '「不许出现括号」这个规则抓错了特征 —— 反引号不需要括号。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0"><span class="c">// 表达式里不许出现括号 —— 思路是「不许调用函数」</span>
<span class="k">foreach</span> ([<span class="s">'('</span>, <span class="s">')'</span>] <span class="k">as</span> $bad) {
    <span class="k">if</span> (<span class="v">strpos</span>($expr, $bad) !== <span class="f">false</span>) {
        <span class="k">return</span> <span class="s">'[已被过滤]'</span>;
    }
}
<span class="k">return</span> <span class="v">eval</span>(<span class="s">'return '</span> . $expr . <span class="s">';'</span>);</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    这次要读文件是走不通了（读文件要用括号）。<br>
    改个目标：让渲染结果里出现 <code><?= htmlspecialchars(SSTI_CMD_MARKER) ?></code> ——
    也就是<b>成功执行一条系统命令</b>，而且<b>表达式里不能出现括号</b>。
  </p>
  <p class="hint" style="margin:12px 0 0">
    关键线索：PHP 里「执行一段 shell 命令」这个能力，
    是不是只有 <code>函数名(...)</code> 这一种写法？
    去翻一下 PHP 的「运算符」章节，而不是「函数」章节。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">通知模板</h3>
  <form method="post" action="medium.php">
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
  <?php render_ssti_expressions($expressions, count($blocked) ? '被过滤器拦下' : ''); ?>

  <?php if ($blocked): ?>
    <div class="card tight" style="margin-bottom:14px">
      <div style="font-size:13px;color:var(--muted);margin-bottom:10px">被过滤器拦下的表达式</div>
      <ul style="margin:0;padding-left:20px;font-size:13px;color:var(--danger)">
        <?php foreach ($blocked as [$expr, $why]): ?>
          <li><code><?= htmlspecialchars($expr) ?></code> —— <?= htmlspecialchars($why) ?></li>
        <?php endforeach; ?>
      </ul>
    </div>
  <?php endif; ?>

  <?php if ($evalError !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)">求值出错：<?= htmlspecialchars($evalError) ?></b>
    </div>
  <?php endif; ?>

  <div class="card" style="<?= $cmdExecuted || $fileRead ? 'border-color:#fecaca;background:var(--danger-soft)' : '' ?>">
    <h3 style="margin-top:0">渲染结果</h3>
    <pre style="margin:0;white-space:pre-wrap"><?= htmlspecialchars($rendered) ?></pre>

    <?php if ($cmdExecuted): ?>
      <p style="margin:12px 0 0;color:var(--danger);font-weight:500">
        ★ 命令被执行了，而且表达式里一个括号都没有 —— 黑名单被绕过
      </p>
    <?php endif; ?>
    <?php if ($fileRead): ?>
      <p style="margin:12px 0 0;color:var(--danger);font-weight:500">
        ★ 读到了演示文件的内容
      </p>
    <?php endif; ?>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">核心绕过点：黑名单抓的是「特征」，不是「能力」</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:26%">防护想禁止的能力</th><th style="width:24%">它抓的特征</th><th>绕过</th></tr></thead>
      <tbody>
        <tr>
          <td>调用函数</td>
          <td class="mono">( )</td>
          <td>
            <b>反引号运算符</b>：<code>`cmd`</code> 等价于 <code>shell_exec('cmd')</code>，
            <b>不需要括号</b>
          </td>
        </tr>
        <tr>
          <td>（对照）SQL 里做联合查询</td>
          <td class="mono">union</td>
          <td>双写 <code>ununionion</code>（Sqli 场景）</td>
        </tr>
        <tr>
          <td>（对照）穿越目录</td>
          <td class="mono">../</td>
          <td>双写 <code>....//</code>（LFI 场景）</td>
        </tr>
        <tr>
          <td>（对照）实例化危险类</td>
          <td class="mono">Cache</td>
          <td>小写 <code>cache</code>（反序列化场景）</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="hint">
    四行省略号里是同一个结构：<b>「特征」和「能力」之间永远是多对多的。</b><br>
    防护者能想到的是「常见的那一种写法」，而语言里表达同一个能力的写法往往不止一种。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>PHP 的「运算符」列表里，有没有哪个是「执行一段命令」的？</li>
    <li>它需要括号吗？</li>
    <li>它的返回值是命令的输出吗，还是把输出直接打印出去？</li>
    <li>跨平台考虑：<code>echo</code> 在 Windows 的 cmd 和 Linux 的 sh 上行为一致，适合做判据。</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/ssti.md</code>。</p>
</div>

<?php layout_footer(); ?>
