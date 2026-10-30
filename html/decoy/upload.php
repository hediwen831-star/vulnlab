<?php
declare(strict_types=1);
require __DIR__ . '/_shell.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    http_response_code(405);
    shell_start('不接收上传');
    ?>
    <div class="card">
      <b>405 Method Not Allowed</b>
      <p>这个页面只用于演示表单，不处理后端上传。</p>
      <a href="upload.php">返回</a>
    </div>
    <?php
    shell_end();
    exit;
}
shell_start('文件上传（只读）');
?>
<p class="sub">有一个上传表单，但服务端没有处理逻辑。任何上传请求都返回 405。</p>
<div class="card">
  <form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <button>上传</button>
  </form>
  <div class="muted">注意：提交后会返回 405，不会保存任何文件。</div>
</div>
<?php shell_end(); ?>
