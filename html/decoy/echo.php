<?php
declare(strict_types=1);
require __DIR__ . '/_shell.php';

$q = isset($_GET['q']) ? (string) $_GET['q'] : '';
shell_start('回显查询词');
?>
<p class="sub">把查询词原样回显在页面上，<b>输出前做 HTML 编码</b>。没有拼接、没有执行。</p>
<form method="get"><input name="q" value="<?= esc($q) ?>" placeholder="随便输点东西"><button>查询</button></form>
<div class="card">
  <div class="muted">你搜索的是</div>
  <pre><?= esc($q) ?></pre>
</div>
<?php shell_end(); ?>
