<?php
/**
 * XSS · medium 档
 *
 * 漏洞成因：用「标签黑名单」做过滤 —— 和 SQL 注入的黑名单是同一个错误。
 *
 * 黑名单的思路是「枚举所有危险的写法然后删掉」。问题在于：
 * HTML 里能触发脚本执行的写法**不是有限个**——
 *
 *   <script>…</script>          script 标签
 *   <img src=x onerror=…>       任意标签 + 事件属性
 *   <svg onload=…>              SVG 事件
 *   <iframe srcdoc=…>           内联文档
 *   <a href="javascript:…">     javascript: 伪协议
 *   …以及它们在各种浏览器解析下的变体
 *
 * 而事件属性有几十种（onerror / onload / onfocus / onmouseover / …），
 * 可以挂在几乎任何标签上。**这是一个组合爆炸的空间，黑名单堵不完。**
 *
 * 本档刻意只过滤了 `<script` 和 `javascript:` —— 这是最典型的
 * 「我加了过滤应该安全了吧」的写法。你要做的就是用它没想到的方式触发。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$name = isset($_GET['name']) ? (string) $_GET['name'] : '';
$submitted = isset($_GET['name']);

// ------------------------------------------------------------------
// 漏洞点：黑名单过滤
//
// 只堵了 script 标签和 javascript: 伪协议，但 HTML 的触发方式是组合空间。
// 另外 str_ireplace 是【单次非递归】替换 —— 嵌套写法可以让它自己把危险片段拼回来。
// ------------------------------------------------------------------
$blacklist = ['<script', '</script', 'javascript:'];
$filtered = str_ireplace($blacklist, '', $name);
$filterChanged = ($filtered !== $name);

$output = $submitted
    ? '<div class="greeting">欢迎回来，' . $filtered . '！</div>'
    : '';

$bypasses = [
    ['<img src=x onerror=alert(1)>', '任意标签 + 事件属性：黑名单完全没覆盖到'],
    ['<svg onload=alert(1)>', 'SVG 的事件属性'],
    ['<scr<script>ipt>alert(1)</script>', '嵌套：单次替换后危险片段被拼回来'],
    ['<img src=x onerror="alert(document.cookie)">', '带上 Cookie 读取'],
];
?>
<?php layout_header(
    'XSS · 难度 medium',
    '标签黑名单过滤 —— 看起来堵住了，实际上只堵住了它想到的那一种。'
); ?>

<?php render_level_switcher(['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'], basename(__FILE__)); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    对输入做标签/关键字黑名单过滤，命中即删除：
  </p>
  <pre style="margin:10px 0 0">$blacklist = [<span class="s">'&lt;script'</span>, <span class="s">'&lt;/script'</span>, <span class="s">'javascript:'</span>];
$filtered  = str_ireplace($blacklist, <span class="s">''</span>, $name);</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    同样让 <code>alert</code> 弹出来，但这次你不能用 <code>&lt;script&gt;</code>。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="medium.php">
    <input type="text" name="name" value="<?= htmlspecialchars($name) ?>"
           placeholder="试试不用 script 标签">
    <button type="submit">提交</button>
  </form>
</div>

<?php if ($submitted): ?>
  <?php if ($filterChanged): ?>
    <div class="card tight" style="background:var(--warn-soft);border-color:#fde68a;margin-bottom:14px">
      <div style="font-size:13px;color:#92400e;margin-bottom:8px">
        过滤器检测到敏感关键字并做了改写
      </div>
      <div class="kv"><b>你的输入</b><span class="mono"><?= htmlspecialchars($name) ?></span></div>
      <div class="kv"><b>过滤后</b><span class="mono"><?= htmlspecialchars($filtered) ?></span></div>
    </div>
  <?php endif; ?>

  <?php render_xss_compare($output); ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">为什么黑名单堵不完（这是本档的核心）</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    能触发脚本执行的写法是一个<b>组合空间</b>，不是一份清单：
  </p>
  <pre style="margin:0">触发点 = 标签 × 事件属性 × 编码方式 × 解析差异

标签      script / img / svg / iframe / a / body / details / …
事件属性  onerror / onload / onfocus / onmouseover / onanimationstart / …
编码方式  大小写 / HTML 实体 / URL 编码 / Unicode / 空字节 / …
解析差异  浏览器容错解析、SVG/MathML 命名空间、…

组合出来的写法有成千上万种，而黑名单只能列出作者想到的那几种。</pre>
  <p class="hint">
    这和 SQL 注入完全同构：<b>黑名单在原理上必然失败，因为你要枚举的是一个无穷集合。</b>
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">可用载荷</h3>
  <table>
    <thead><tr><th style="width:52%">载荷</th><th>绕过原理</th></tr></thead>
    <tbody>
      <?php foreach ($bypasses as [$payload, $note]): ?>
        <tr>
          <td class="mono" style="word-break:break-all"><?= htmlspecialchars($payload) ?></td>
          <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>过滤器删的是哪几个词？把它们列出来，问你：<b>要弹窗只能靠这几个词吗？</b></li>
    <li>除了 <code>&lt;script&gt;</code>，还有哪些标签可以"在加载时自动做点什么"？</li>
    <li>如果过滤器是「删除匹配到的内容」，那<b>删除之后的字符串会变成什么</b>？
        观察上面「过滤后」那一行。</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/xss.md</code>。</p>
</div>

<?php layout_footer(); ?>
