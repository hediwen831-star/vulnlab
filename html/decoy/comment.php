<?php
declare(strict_types=1);
require __DIR__ . '/_shell.php';

session_start();
$comments = $_SESSION['decoy_comments'] ?? [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $content = trim((string) ($_POST['content'] ?? ''));
    if ($content !== '') {
        $comments[] = mb_substr($content, 0, 200);
        $_SESSION['decoy_comments'] = array_slice($comments, -5);
    }
}
shell_start('留言板');
?>
<p class="sub">留言会保存到会话并展示，展示时统一编码。没有持久化，也没有富文本。</p>
<form method="post">
  <input name="content" placeholder="写点什么" value="">
  <button>发布</button>
</form>
<div class="card">
<?php if (!$comments): ?>
  <span class="muted">还没有留言。</span>
<?php else: ?>
  <?php foreach (array_reverse($comments) as $item): ?>
    <div style="padding:8px 0;border-bottom:1px solid #eef2f7">
      <div class="muted">匿名访客</div>
      <div><?= esc($item) ?></div>
    </div>
  <?php endforeach; ?>
<?php endif; ?>
</div>
<?php shell_end(); ?>
