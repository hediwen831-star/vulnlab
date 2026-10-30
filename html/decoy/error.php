<?php
declare(strict_types=1);
require __DIR__ . '/_shell.php';

$msg = isset($_GET['msg']) ? (string) $_GET['msg'] : '请求参数有误';
http_response_code(400);
shell_start('请求出错');
?>
<p class="sub">错误页会把服务端消息带出来，但消息同样经过编码。</p>
<div class="card">
  <b>400 Bad Request</b>
  <pre><?= esc($msg) ?></pre>
  <a href="index.php">返回诱饵页集合</a>
</div>
<?php shell_end(); ?>
