<?php
/**
 * SQL 注入 · low 档
 *
 * 漏洞成因：用户输入被直接拼接进 SQL 语句，没有任何类型校验与过滤。
 *
 * 这一档的意义在于「把问题暴露到最明显」：
 * 页面会把服务端实际执行的语句原样贴出来，
 * 你能直观看到自己输入的内容是怎样变成 SQL 语法的一部分的。
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
// 没有引号包围 → 数字型注入：连引号都不需要闭合
// 没有强制转换   → 字符串输入会被直接当成 SQL 语法解析
// 没有预处理     → 数据库无法区分「代码」与「数据」
//
// 正确做法见同目录 high.php。
// ------------------------------------------------------------------
$sql = "SELECT id, username, email, role FROM users WHERE id = $id";

$rows = [];
$error = '';
if ($submitted) {
    try {
        $rows = db()->query($sql)->fetchAll();
    } catch (PDOException $e) {
        // 故意回显数据库错误 —— 报错信息是注入过程中最重要的反馈
        $error = $e->getMessage();
    }
}
?>
<?php layout_header(
    'SQL 注入 · 难度 low',
    '用户输入被直接拼接进 SQL 语句，没有任何校验。'
); ?>

<?php render_level_switcher(['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'], basename(__FILE__)); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    没有任何防护。参数被 <code>$_GET</code> 取出后直接拼进 SQL 字符串。
  </p>
  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    查询目标表 <code>users</code>，读取 <code>admin</code> 用户的 <code>secret</code> 字段。
    注意：页面的 SQL 只 <code>SELECT</code> 了四列，<b>不含 secret</b> ——
    也就是说，光靠猜参数值拿不到目标，必须改变语句结构。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="low.php">
    <input type="text" name="id" value="<?= htmlspecialchars($id) ?>"
           placeholder="输入用户 id，例如 1">
    <button type="submit">查询</button>
  </form>
  <p class="hint">
    正常使用：<code>?id=1</code> / <code>?id=2</code> …
  </p>
</div>

<?php if ($submitted): ?>
  <?php render_sql_board($sql); ?>

  <?php if ($error !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)">数据库错误</b>
      <pre style="margin:10px 0 0;background:#fff;color:#7f1d1d;border:1px solid #fecaca"><?= htmlspecialchars($error) ?></pre>
      <p class="hint" style="color:#b91c1c">
        报错信息会告诉你语句在哪里断掉了 —— 这是调试注入 payload 的主要依据。
      </p>
    </div>
  <?php endif; ?>

  <?php if ($error === ''): ?>
    <div class="card">
      <h3 style="margin-top:0">查询结果</h3>
      <?php render_users_table($rows); ?>
      <?php
      $found = false;
      foreach ($rows as $row) {
          if (isset($row['secret'])) {
              $found = true;
          }
      }
      ?>
      <?php if (!$found && !empty($rows)): ?>
        <p class="hint">
          结果里出现了 <code>secret</code> 列 —— 说明你已经改变了语句结构，拿到目标字段了。
        </p>
      <?php endif; ?>
    </div>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>观察 SQL 黑板：你输入的内容出现在语句的哪个位置？<b>它有没有被引号包围？</b></li>
    <li>既然没有引号，你还需要闭合引号吗？</li>
    <li>页面只查了四列。如果想看到第五列（<code>secret</code>），
        你需要让数据库<b>返回一个不同的结果集</b>，而不是换一个 id。</li>
  </ul>
  <p class="hint">
    卡住了就看 <code>writeups/sqli.md</code>，里面有完整推导过程。
  </p>
</div>

<?php layout_footer(); ?>
