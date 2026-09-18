<?php
/**
 * 文件上传 · medium 档
 *
 * 漏洞成因：**只验证了客户端声明的 MIME 类型**（`$_FILES['file']['type']`）。
 *
 * 这是最经典的「看起来校验了，实际完全没校验」的写法。
 *
 * 关键认知：`$_FILES['file']['type']` 的值来自 multipart 请求体里
 * 每一段前面的 `Content-Type` 头 —— **那是客户端自己写的**。
 * 浏览器上传时它会根据文件扩展名自动填一个，但请求是可以手工构造的：
 *
 *     curl -F "file=@shell.php;type=image/jpeg" http://target/upload/medium.php
 *                                                    ^^^^^^^^^^^^^^^^^
 *                                                    这一行完全由你决定
 *
 * 所以服务端检查它，等于让攻击者自己声明「我是良民」然后放行 ——
 * **永远不要相信客户端提供的任何元数据。**
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

const UPLOAD_DIR = __DIR__ . '/../uploads';
const UPLOAD_URL = '/uploads';

if (!is_dir(UPLOAD_DIR)) {
    @mkdir(UPLOAD_DIR, 0777, true);
}

/** 服务端「以为」允许的类型 */
const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/gif'];

$result = null;
$error = '';
$rejectedType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        $error = '上传失败，错误码：' . $file['error'];
    } else {
        // ------------------------------------------------------------------
        // 漏洞点：只检查客户端声明的 Content-Type
        //
        // 这个值来自请求体里的 multipart 分段头，攻击者可以随意设置。
        // 正确的做法是检查**文件内容本身**（getimagesize / finfo），
        // 或者更彻底：白名单后缀 + 重命名 + 目录禁止执行。
        // ------------------------------------------------------------------
        if (!in_array($file['type'], ALLOWED_MIME, true)) {
            $rejectedType = $file['type'];
            $error = '只允许上传图片文件（服务端认为你传的是：' . htmlspecialchars($file['type']) . '）';
        } else {
            $target = UPLOAD_DIR . '/' . $file['name'];

            if (move_uploaded_file($file['tmp_name'], $target)) {
                $result = [
                    'name' => $file['name'],
                    'size' => $file['size'],
                    'type' => $file['type'],
                    'url'  => UPLOAD_URL . '/' . $file['name'],
                ];
            } else {
                $error = '文件保存失败，请检查 uploads 目录权限。';
            }
        }
    }
}

$uploaded = [];
if (is_dir(UPLOAD_DIR)) {
    foreach (scandir(UPLOAD_DIR) ?: [] as $entry) {
        if ($entry !== '.' && $entry !== '..') {
            $uploaded[] = $entry;
        }
    }
}
?>
<?php layout_header(
    '文件上传 · 难度 medium',
    '只校验客户端声明的 MIME 类型 —— 等于让攻击者自己说「我是良民」。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    上传类漏洞利用成功后通常直接等于服务器失陷。仅在本地靶场练习。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$allowed = [<span class="s">'image/jpeg'</span>, <span class="s">'image/png'</span>, <span class="s">'image/gif'</span>];

<span class="c">// 检查的是 $file['type'] —— 它来自请求体里的 multipart 分段头</span>
if (!in_array($file[<span class="s">'type'</span>], $allowed, true)) {
    <span class="c">// 拒绝</span>
}</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    同样上传一个可执行脚本并让它执行。文件名这次会被检查类型 ——
    但检查的依据是什么？
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">为什么浏览器上传骗不过它</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    用浏览器直接传 <code>.php</code>，浏览器会诚实地填
    <code>Content-Type: application/x-php</code>，于是被拦下。
    所以这个漏洞<b>需要你手工构造请求</b> —— 这也是它比 low 档更接近真实场景的地方：
    真实渗透中，攻击者当然不会用浏览器。
  </p>
  <p style="margin:10px 0 0;font-size:14px;color:var(--muted)">
    提示：用用 <code>curl</code> 的 <code>-F</code> 参数，或者用 Burp 拦截改包。
  </p>
</div>

<div class="card">
  <form method="post" action="medium.php" enctype="multipart/form-data">
    <div class="row">
      <input type="file" name="file" style="flex:1;min-width:240px">
      <button type="submit">上传</button>
    </div>
  </form>
  <p class="hint">
    服务端允许的类型：<code><?= implode('</code> <code>', ALLOWED_MIME) ?></code>
  </p>
</div>

<?php if ($error !== ''): ?>
  <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
    <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
    <?php if ($rejectedType !== ''): ?>
      <p style="margin:8px 0 0;font-size:14px;color:#b91c1c">
        服务端看到的类型是 <code><?= htmlspecialchars($rejectedType) ?></code> ——
        这个值来自于<b>你发出的请求</b>。
      </p>
    <?php endif; ?>
  </div>
<?php endif; ?>

<?php if ($result !== null): ?>
  <div class="card tight" style="background:var(--warn-soft);border-color:#fde68a">
    <div style="font-size:13px;color:#92400e;margin-bottom:8px">上传成功</div>
    <div class="kv"><b>文件名</b><span class="mono"><?= htmlspecialchars($result['name']) ?></span></div>
    <div class="kv"><b>声明类型</b><span class="mono"><?= htmlspecialchars($result['type']) ?></span></div>
    <div class="kv"><b>大小</b><span class="mono"><?= (int) $result['size'] ?> 字节</span></div>
    <div class="kv"><b>可访问地址</b>
      <a class="mono" href="<?= htmlspecialchars($result['url']) ?>" target="_blank">
        <?= htmlspecialchars($result['url']) ?>
      </a>
    </div>
  </div>
  <?php render_code_board(
      '服务端相信了什么',
      "客户端声明: Content-Type = {$result['type']}\n"
      . "服务端判断: in_array('{$result['type']}', ALLOWED_MIME) → 通过\n"
      . "服务端保存: " . UPLOAD_DIR . "/{$result['name']}\n\n"
      . "整个过程里，服务端【没有看过文件内容一眼】。"
  ); ?>
<?php endif; ?>

<?php if ($uploaded): ?>
  <div class="card">
    <h3 style="margin-top:0">uploads 目录现有文件</h3>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>文件名</th><th style="width:120px">访问</th></tr></thead>
        <tbody>
          <?php foreach ($uploaded as $name): ?>
            <tr>
              <td class="mono"><?= htmlspecialchars($name) ?></td>
              <td><a href="<?= UPLOAD_URL ?>/<?= rawurlencode($name) ?>" target="_blank">打开</a></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li><code>$_FILES['file']['type']</code> 这个值，是谁填的？在请求的哪个位置？</li>
    <li>浏览器上传和 <code>curl</code> 上传有什么区别？为什么后者能绕过？</li>
    <li>如果服务端改成「检查文件真实内容」，你还打得通吗？（想想 <code>getimagesize</code>）</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/upload.md</code>。</p>
</div>

<?php layout_footer(); ?>
