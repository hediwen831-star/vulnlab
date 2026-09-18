<?php
/**
 * XSS · high 档 —— 修复对照
 *
 * 修复手段：**输出编码**（也叫上下文转义）。
 *
 * 核心原理只有一句话：
 *
 *   XSS 的本质是「数据被当成了 HTML 语法」，
 *   所以修复方式就是「把数据里所有可能被解析成语法的字符，转成纯文本表示」。
 *
 * `htmlspecialchars` 做的事就是：把 `<` 变成 `&lt;`、`>` 变成 `&gt;`、
 * `"` 变成 `&quot;` 等。这样浏览器收到的是「一段显示内容」，
 * 而不是「一个标签」。用户输入还是原样，只是不再参与语法解析。
 *
 * 注意和 SQL 注入的修复对比：
 *
 *   SQL 注入 → 参数化查询（改变**数据传递方式**，让数据不参与语法解析）
 *   XSS      → 输出编码    （改变**数据表示形式**，让数据不参与语法解析）
 *
 * 手段不同，思路完全一致：**让数据待在数据的位置上。**
 *
 * ══════════════════════════════════════════════════════════════════
 * ⚠️ 进阶：htmlspecialchars 不是万能的
 * ══════════════════════════════════════════════════════════════════
 *
 * 它只对「HTML 文本上下文」有效。同一个变量输出到不同位置，
 * 需要不同的编码方式 —— 这是很多"明明用了 htmlspecialchars 还是被 XSS"
 * 的真实原因：
 *
 *   输出位置                       需要的编码
 *   ────────────────────────────  ──────────────────────────────
 *   <div> 内容 </div>              htmlspecialchars
 *   <div title="值">               htmlspecialchars（必须带 ENT_QUOTES）
 *   <script>var a = "值"</script>  json_encode + 转义 </script>
 *   <a href="值">                  urlencode + 协议白名单校验
 *   未加引号的属性 <div class=值>   不能只靠转义，必须加引号
 *
 * **编码方式必须匹配输出上下文**，这是本档最值得记住的一句话。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$name = isset($_GET['name']) ? (string) $_GET['name'] : '';
$submitted = isset($_GET['name']);

// ------------------------------------------------------------------
// 这里是修复方案。
//
// ENT_QUOTES  —— 同时转义单引号和双引号（默认只转双引号），
//                因为属性值可能用单引号包裹。
// ENT_SUBSTITUTE —— 遇到非法 UTF-8 序列时用替代字符，而不是返回空串。
//                不加这个的话，构造的非法编码输入能让整个输出变成空字符串。
// 'UTF-8'      —— 显式指定字符集。**不指定是危险的**：
//                某些宽字节字符集下，转义可能被绕过（历史上真实出现过）。
// ------------------------------------------------------------------
$safeName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$output = $submitted
    ? '<div class="greeting">欢迎回来，' . $safeName . '！</div>'
    : '';

/** 对照：同样的输入，在本档与 low 档分别会输出成什么 */
$compareSamples = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
];
?>
<?php layout_header(
    'XSS · 难度 high（已修复）',
    '输出编码 + 上下文意识 —— 这一档打不动，作为修复对照保留。'
); ?>

<?php render_level_switcher(['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'], basename(__FILE__)); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护</h3>
  <p style="margin:0 0 10px;font-size:14px;color:#065f46">
    在**输出的那一刻**做编码，而不是在输入的时候做过滤：
  </p>
  <pre style="margin:0;background:#064e3b">$safeName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, <span class="s">'UTF-8'</span>);
$output   = <span class="s">'&lt;div&gt;欢迎回来，'</span> . $safeName . <span class="s">'！&lt;/div&gt;'</span>;</pre>
  <p style="margin:10px 0 0;font-size:14px;color:#065f46">
    用户输入完全没变，只是它在 HTML 里变成了「显示内容」而不是「标签」。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="high.php">
    <input type="text" name="name" value="<?= htmlspecialchars($name) ?>"
           placeholder="把 low / medium 档成功的载荷粘进来试试">
    <button type="submit">提交</button>
  </form>
  <p class="hint">不会弹窗 —— 载荷会原样显示成一段文字。</p>
</div>

<?php if ($submitted): ?>
  <?php render_xss_compare($output); ?>
  <div class="card tight" style="background:var(--ok-soft);border-color:#a7f3d0">
    <b style="color:var(--ok)">观察上面 ① 和 ② —— 现在它们长得一样了。</b>
    <p style="margin:8px 0 0;font-size:14px;color:#065f46">
      <code>&lt;</code> 变成了 <code>&amp;lt;</code>，
      浏览器就不再把它当作标签的开始，而是当作一个要显示的字符。
      <b>数据回到了数据的位置上。</b>
    </p>
  </div>
<?php endif; ?>

<h2>对照实验：同一段输入，两档的输出差异</h2>
<p class="sub" style="margin-bottom:12px">
  下面这些载荷在 low / medium 档会执行，在 high 档只会原样显示。
</p>
<div class="tbl-wrap">
  <table>
    <thead>
      <tr>
        <th style="width:34%">原始输入</th>
        <th style="width:33%">low 档输出（危险）</th>
        <th style="width:33%">high 档输出（安全）</th>
      </tr>
    </thead>
    <tbody>
      <?php foreach ($compareSamples as $sample): ?>
        <tr>
          <td class="mono" style="word-break:break-all"><?= htmlspecialchars($sample) ?></td>
          <td class="mono" style="word-break:break-all;color:var(--danger)">
            <?= htmlspecialchars($sample) ?>
          </td>
          <td class="mono" style="word-break:break-all;color:var(--ok)">
            <?= htmlspecialchars(htmlspecialchars($sample, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')) ?>
          </td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>

<h2>输出上下文对照表</h2>
<p class="sub" style="margin-bottom:12px">
  <b>「我用了 htmlspecialchars 还是被 XSS」的根本原因，通常是编码方式没匹配输出位置。</b>
</p>
<div class="tbl-wrap">
  <table>
    <thead><tr><th style="width:42%">输出位置</th><th>需要的处理</th></tr></thead>
    <tbody>
      <tr>
        <td class="mono">&lt;div&gt; <b>值</b> &lt;/div&gt;</td>
        <td><code>htmlspecialchars</code>（HTML 文本上下文）</td>
      </tr>
      <tr>
        <td class="mono">&lt;div title="<b>值</b>"&gt;</td>
        <td><code>htmlspecialchars</code> 且必须带 <code>ENT_QUOTES</code></td>
      </tr>
      <tr>
        <td class="mono">&lt;script&gt;var a = "<b>值</b>"&lt;/script&gt;</td>
        <td>不能用 HTML 编码 —— 需要 <code>json_encode</code> 并转义 <code>&lt;/script&gt;</code></td>
      </tr>
      <tr>
        <td class="mono">&lt;a href="<b>值</b>"&gt;</td>
        <td><code>urlencode</code> + <b>协议白名单</b>（否则 <code>javascript:</code> 仍可执行）</td>
      </tr>
      <tr>
        <td class="mono">&lt;div class=<b>值</b>&gt;（无引号）</td>
        <td>转义救不了 —— 必须给属性加引号</td>
      </tr>
      <tr>
        <td class="mono">CSS / style 属性内</td>
        <td>需要 CSS 编码，且应禁止用户控制样式</td>
      </tr>
    </tbody>
  </table>
</div>

<div class="card" style="margin-top:20px">
  <h3 style="margin-top:0">修复要点总结</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>在输出时编码，不要在输入时过滤。</b>
      原因：同一份数据可能同时用于 HTML、JSON、数据库、日志，
      在输入阶段就"洗一遍"既会破坏原始数据，又无法针对具体上下文编码。
    </li>
    <li>
      <b>编码方式必须匹配输出上下文。</b>
      这是「用了 htmlspecialchars 还是中招」的头号原因。见上面的对照表。
    </li>
    <li>
      <b>能用框架的自动转义就用。</b>
      Vue / React 默认对插值做转义（<code>{{ }}</code>、<code>{value}</code>），
      但要小心 <code>v-html</code> / <code>dangerouslySetInnerHTML</code> 这类逃生舱。
    </li>
    <li>
      <b>配合 CSP 做纵深防御。</b>
      即使漏了一处 XSS，严格的 <code>Content-Security-Policy</code>
      也能阻止内联脚本执行。它不是替代品，是保险。
    </li>
    <li>
      <b>Cookie 加 HttpOnly。</b>
      这样即使 XSS 发生，攻击者也读不到会话 Cookie —— 把「XSS」限制在
      「钓鱼/篡改页面」而不是「直接接管账号」。
    </li>
  </ul>
</div>

<?php layout_footer(); ?>
