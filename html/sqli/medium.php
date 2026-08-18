<?php
/**
 * SQL 注入 · medium 档
 *
 * 漏洞成因：用了「关键字黑名单」做过滤 —— 这是最典型的伪安全措施。
 *
 * 本档的教学重点是 **黑名单为什么必然被绕过**：
 *
 *   黑名单的本质是「枚举所有危险词」。但 SQL 语法是无穷的：
 *   大小写、注释、编码、等价函数、双写 —— 每种变形都能绕过枚举。
 *   而白名单（只允许合法输入）和类型转换（只允许数字）没有这个问题，
 *   因为它们定义的是「什么是允许的」，而不是「什么是不允许的」。
 *
 * 另外注意这里的选择：注入点是**字符型**（被单引号包围），
 * 与 low 档的数字型形成对比 —— 你需要先闭合引号才能改变语句结构。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$id = isset($_GET['id']) ? (string) $_GET['id'] : '1';
$submitted = isset($_GET['id']);

// ------------------------------------------------------------------
// 漏洞点在这里。
//
// str_ireplace 是「一次性、非递归」替换：
// 它在原字符串上查找并删除匹配项，但**不会重新扫描替换后的结果**。
// 于是 "ununionion" 删掉中间的 "union" 之后，剩下的 "un" + "ion"
// 正好拼回 "union" —— 这就是「双写绕过」。
//
// 同理 "seselectlect" → "select"，"frfromom" → "from"。
//
// 只要黑名单里有任何一个词可以被用这种方式还原，过滤就形同虚设。
// ------------------------------------------------------------------
$blacklist = ['union', 'select', 'from', 'where'];
$filtered = str_ireplace($blacklist, '', $id);

$sql = "SELECT id, username, email, role FROM users WHERE id = '$filtered'";

$rows = [];
$error = '';
$filterChanged = ($filtered !== $id);

if ($submitted) {
    try {
        $rows = db()->query($sql)->fetchAll();
    } catch (PDOException $e) {
        $error = $e->getMessage();
    }
}
?>
<?php layout_header(
    'SQL 注入 · 难度 medium',
    '关键字黑名单过滤 —— 看起来有防护，实际上只是提高了攻击成本。'
); ?>

<?php render_level_switcher(['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'], basename(__FILE__)); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    对输入做关键字黑名单过滤，命中即删除：
  </p>
  <pre style="margin:10px 0 0">$blacklist = [<span class="s">'union'</span>, <span class="s">'select'</span>, <span class="s">'from'</span>, <span class="s">'where'</span>];
$filtered  = str_ireplace($blacklist, <span class="s">''</span>, $id);
$sql = <span class="s">"SELECT ... WHERE id = '$filtered'"</span>;</pre>
  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    和 low 档一样：读到 <code>admin</code> 的 <code>secret</code>。
    但直接抄 low 档的 payload 会被过滤掉关键字 —— 你得先想办法让过滤失效。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="medium.php">
    <input type="text" name="id" value="<?= htmlspecialchars($id) ?>"
           placeholder="输入用户 id，例如 1">
    <button type="submit">查询</button>
  </form>
</div>

<?php if ($submitted): ?>
  <?php
  // 把过滤前后的对比也展示出来 —— 否则学生看不到「过滤器做了什么」
  if ($filterChanged):
      ?>
      <div class="card tight" style="background:var(--warn-soft);border-color:#fde68a">
        <div style="font-size:13px;color:#92400e;margin-bottom:8px">
          过滤器检测到敏感关键字并做了改写
        </div>
        <div class="kv"><b>你的输入</b><span class="mono"><?= htmlspecialchars($id) ?></span></div>
        <div class="kv"><b>过滤后</b><span class="mono"><?= htmlspecialchars($filtered) ?></span></div>
      </div>
      <?php
  endif;
  ?>

  <?php render_sql_board($sql); ?>

  <?php if ($error !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)">数据库错误</b>
      <pre style="margin:10px 0 0;background:#fff;color:#7f1d1d;border:1px solid #fecaca"><?= htmlspecialchars($error) ?></pre>
    </div>
  <?php endif; ?>

  <?php if ($error === ''): ?>
    <div class="card">
      <h3 style="margin-top:0">查询结果</h3>
      <?php render_users_table($rows); ?>
    </div>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>先看 low 档的 SQL 黑板，对比这一档 —— 注意 <code>id</code> 现在<b>被单引号包围了</b>。
        你需要先闭合这个引号，才能继续写自己的语法。</li>
    <li>你的输入会被「删除」某些词。想一想：<b>删除操作是只做一次，还是会反复做？</b>
        如果只做一次，你能否构造一个删掉之后刚好变成你想要的词？</li>
    <li>被删掉关键词之后，整条语句还剩下什么？观察上面「过滤后」那行。</li>
    <li>语句末尾多出来的那个单引号怎么处理？（想想 SQL 里的注释符号）</li>
  </ul>
  <p class="hint">
    完整推导见 <code>writeups/sqli.md</code>。
  </p>
</div>

<?php layout_footer(); ?>
