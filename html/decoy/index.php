<?php
declare(strict_types=1);
require __DIR__ . '/_shell.php';
shell_start('诱饵页集合');
?>
<p class="sub">这些页面接受输入、会回显，但输出全部经过编码。扫描器在这里报出的任何漏洞都是误报。</p>
<ul>
  <li><a href="echo.php?q=hello">echo.php</a> —— 回显查询词</li>
  <li><a href="search.php?q=hello">search.php</a> —— 搜索无结果提示</li>
  <li><a href="error.php?msg=bad">error.php</a> —— 参数化错误页</li>
  <li><a href="preview.php">preview.php</a> —— 文本预览</li>
  <li><a href="comment.php">comment.php</a> —— 留言板</li>
  <li><a href="json.php?q=hello">json.php</a> —— JSON 回显</li>
  <li><a href="redirect.php?to=home">redirect.php</a> —— 白名单跳转</li>
  <li><a href="download.php?file=sample">download.php</a> —— 固定文件下载</li>
  <li><a href="log.php?q=hello">log.php</a> —— 查询日志</li>
  <li><a href="upload.php">upload.php</a> —— 只读上传页</li>
</ul>
<?php shell_end(); ?>
