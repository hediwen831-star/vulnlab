<?php
/**
 * 文件上传 · low 档
 *
 * 漏洞成因：对上传文件**不做任何校验**，且用**用户提供的文件名**保存到可访问目录。
 *
 * 这里有两个独立的错误叠加：
 *
 *   ① 不校验类型 —— 任何文件都能传，包括可执行脚本
 *   ② 用原名保存 —— 攻击者可以控制文件在服务器上的名字（进而控制后缀）
 *
 * 只要这两条同时成立，上传一个 `.php` 文件就能直接在服务器上执行代码。
 * 这类漏洞在真实世界里的后果通常是**直接失陷**（getshell），
 * 比信息泄露类漏洞严重得多。
 *
 * ⚠️⚠️ 强烈提醒：本场景的危险性高于其他场景。
 *      请只在本地靶场中使用，不要对任何非授权目标尝试上传。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

// 上传目录与访问前缀
const UPLOAD_DIR = __DIR__ . '/../uploads';
const UPLOAD_URL = '/uploads';

if (!is_dir(UPLOAD_DIR)) {
    @mkdir(UPLOAD_DIR, 0777, true);
}

$result = null;
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        $error = '上传失败，错误码：' . $file['error'];
    } else {
        // ------------------------------------------------------------------
        // 漏洞点：原名保存 + 零校验
        // ------------------------------------------------------------------
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

/** 列出已上传的文件 */
$uploaded = [];
if (is_dir(UPLOAD_DIR)) {
    foreach (scandir(UPLOAD_DIR) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $uploaded[] = $entry;
    }
}
?>
<?php layout_header(
    '文件上传 · 难度 low',
    '零校验 + 原名保存 —— 上传的东西会被原样放到能被访问到的位置。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    上传类漏洞一旦被利用，通常直接等于<b>服务器失陷</b>（getshell），
    后果比信息泄露类漏洞严重得多。<br>
    请只在本地靶场练习；对任何非授权目标尝试上传都是违法的。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">没有任何防护：</p>
  <pre style="margin:10px 0 0">$target = UPLOAD_DIR . <span class="s">'/'</span> . $file[<span class="s">'name'</span>];   <span class="c">// 用户给什么名字就用什么名字</span>
move_uploaded_file($file[<span class="s">'tmp_name'</span>], $target);</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    上传一个可执行脚本，并通过访问它让服务器执行你的代码。
    门槛很低 —— 你需要想的只有一件事：<b>传什么后缀？</b>
  </p>
</div>

<div class="card">
  <form method="post" action="low.php" enctype="multipart/form-data">
    <div class="row">
      <input type="file" name="file" style="flex:1;min-width:240px">
      <button type="submit">上传</button>
    </div>
  </form>
</div>

<?php if ($error !== ''): ?>
  <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
    <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
  </div>
<?php endif; ?>

<?php if ($result !== null): ?>
  <div class="card tight" style="background:var(--warn-soft);border-color:#fde68a">
    <div style="font-size:13px;color:#92400e;margin-bottom:8px">上传成功</div>
    <div class="kv"><b>文件名</b><span class="mono"><?= htmlspecialchars($result['name']) ?></span></div>
    <div class="kv"><b>大小</b><span class="mono"><?= (int) $result['size'] ?> 字节</span></div>
    <div class="kv"><b>客户端声明类型</b><span class="mono"><?= htmlspecialchars($result['type']) ?></span></div>
    <div class="kv"><b>可访问地址</b>
      <a class="mono" href="<?= htmlspecialchars($result['url']) ?>" target="_blank">
        <?= htmlspecialchars($result['url']) ?>
      </a>
    </div>
  </div>
  <?php render_code_board(
      '服务端做的事就是两行 —— 保存、然后告诉你可以访问',
      "move_uploaded_file(\$file['tmp_name'], " . UPLOAD_DIR . "/{$result['name']});\n"
      . "// 最终落到磁盘上的路径：\n"
      . UPLOAD_DIR . "/{$result['name']}"
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
    <p class="hint">
      注意：这些文件是<b>真实存在于磁盘上</b>的。删掉它们只需手动清理
      <code>html/uploads/</code> 目录。
    </p>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>服务端有没有检查你的文件<b>是什么</b>？</li>
    <li>保存到磁盘时用的文件名，是谁决定的？</li>
    <li>这个目录下的文件，能不能通过浏览器直接访问到？被访问时会发生什么？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/upload.md</code>。</p>
</div>

<?php layout_footer(); ?>
