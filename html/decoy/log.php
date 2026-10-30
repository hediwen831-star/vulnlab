<?php
declare(strict_types=1);
require __DIR__ . '/_shell.php';

$q = isset($_GET['q']) ? (string) $_GET['q'] : '';
shell_start('查询日志');
?>
<p class="sub">模拟「把本次查询写进日志并展示」，日志内容输出时编码。</p>
<form method="get"><input name="q" value="<?= esc($q) ?>" placeholder="查询词"><button>记录</button></form>
<div class="card">
  <div class="muted">最近一次查询</div>
  <pre>[<?= date('H:i:s') ?>] query=<?= esc($q) ?></pre>
  <div class="muted">日志只在本次请求内展示，不落盘。</div>
</div>
<?php shell_end(); ?>
