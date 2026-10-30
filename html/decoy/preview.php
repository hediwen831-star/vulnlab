<?php
declare(strict_types=1);
require __DIR__ . '/_shell.php';

$text = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $text = isset($_POST['text']) ? (string) $_POST['text'] : '';
}
shell_start('文本预览');
?>
<p class="sub">预览框会把提交的文本显示两次（编辑区与结果区），两处都做了编码。</p>
<form method="post">
  <textarea name="text" rows="5" placeholder="输入要预览的文本"><?= esc($text) ?></textarea>
  <button>预览</button>
</form>
<div class="card">
  <div class="muted">预览结果</div>
  <pre><?= esc($text) ?></pre>
</div>
<?php shell_end(); ?>
