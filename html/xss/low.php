<?php
/**
 * XSS（跨站脚本）· low 档
 *
 * 漏洞成因：把用户输入**原样拼接**进 HTML 输出。
 *
 * 这是最基础的反射型 XSS。关键在于理解一点：
 *
 *   在 HTML 里，`<` 这个字符是**语法的一部分**，不是普通文本。
 *
 * 所以当用户输入里带 `<script>` 时，浏览器不会把它当成"用户说的一句话"，
 * 而是会当成"一段要执行的代码"—— 因为从浏览器的视角看，
 * 服务端返回的这一整块内容都是**可信的页面代码**。
 *
 * 这和 SQL 注入是同一个根因：**数据被放进了代码的位置**。
 * 区别只在于一个是数据库解析，一个是浏览器解析。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$name = isset($_GET['name']) ? (string) $_GET['name'] : '';
$submitted = isset($_GET['name']);

// ------------------------------------------------------------------
// 漏洞点：没有任何转义，直接拼进 HTML
// ------------------------------------------------------------------
$output = $submitted
    ? '<div class="greeting">欢迎回来，' . $name . '！</div>'
    : '';

/** 演示用的 XSS 载荷（放在页面上是为了让学生有东西可试，不是必须） */
$samplePayloads = [
    '<script>alert(document.domain)</script>' => '最经典的弹窗',
    '<img src=x onerror=alert(1)>'           => '图片加载失败触发',
    '<svg onload=alert(1)>'                  => 'SVG 事件触发',
    '<body onpageshow=alert(1)>'             => '页面事件触发',
];
?>
<?php layout_header(
    'XSS · 难度 low',
    '用户输入被原样拼接进 HTML —— 浏览器把「数据」当成了「代码」。'
); ?>

<?php render_level_switcher(['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'], basename(__FILE__)); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    没有任何防护，输入直接拼进 HTML：
  </p>
  <pre style="margin:10px 0 0">$output = <span class="s">'&lt;div&gt;欢迎回来，'</span> . $name . <span class="s">'！&lt;/div&gt;'</span>;</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    让 <code>alert(document.domain)</code> 在页面上执行。
    页面下方会并排显示「服务端输出的 HTML」和「浏览器解析的结果」——
    对比这两者，就能看清 XSS 到底是怎么发生的。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="low.php">
    <input type="text" name="name" value="<?= htmlspecialchars($name) ?>"
           placeholder="输入你的名字，或者……别的什么">
    <button type="submit">提交</button>
  </form>
  <p class="hint">试试直接粘贴下面这些载荷。</p>
</div>

<?php if ($submitted): ?>
  <?php render_xss_compare($output); ?>

  <div class="card">
    <h3 style="margin-top:0">服务端这次到底输出了什么</h3>
    <p style="margin:0 0 8px;font-size:14px;color:var(--muted)">
      上面 ① 是「源代码视角」——注意看你的输入**原封不动**地躺在 HTML 里。
      上面 ② 是「浏览器视角」——浏览器看到 <code>&lt;script&gt;</code> 就真的去执行了。
    </p>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">可用载荷</h3>
  <table>
    <thead><tr><th style="width:60%">载荷</th><th>说明</th></tr></thead>
    <tbody>
      <?php foreach ($samplePayloads as $payload => $note): ?>
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
    <li>先想清楚一个问题：<b>服务端输出的内容，浏览器凭什么相信它？</b></li>
    <li>你需要构造的载荷要满足什么条件？（提示：必须能形成合法的 HTML 标签）</li>
    <li>重点看 ① 和 ② 的差异 —— 差异出现的位置，就是漏洞发生的位置。</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/xss.md</code>。</p>
</div>

<?php layout_footer(); ?>
