<?php
declare(strict_types=1);
require __DIR__ . '/_shell.php';

$q = isset($_GET['q']) ? trim((string) $_GET['q']) : '';
shell_start('搜索');
?>
<p class="sub">固定数据源上的搜索，结果为空时把关键词回显在提示里。</p>
<form method="get"><input name="q" value="<?= esc($q) ?>" placeholder="关键词"><button>搜索</button></form>
<div class="card">
<?php if ($q === ''): ?>
  <span class="muted">输入关键词开始搜索。</span>
<?php else: ?>
  没有找到与 <code><?= esc($q) ?></code> 相关的结果。
  <div class="muted">已搜索 1 个数据源，耗时 0.002s。</div>
<?php endif; ?>
</div>
<?php shell_end(); ?>
