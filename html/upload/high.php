<?php
/**
 * 文件上传 · high 档 —— 修复对照
 *
 * 上传功能的防护需要**多层叠加**，因为任何单层都有被绕过的可能：
 *
 *   ① 后缀白名单      —— 只允许图片后缀
 *   ② 内容真实性检查  —— 用 getimagesize 确认它真的是图片
 *   ③ 重命名          —— 不让攻击者控制文件名（也就控制了后缀）
 *   ④ 目录禁止执行    —— 最后一道，即使前面全被绕过，脚本也执行不了
 *
 * 为什么必须是多层：
 *
 *   · 只有 ① → 双后缀（shell.php.jpg）、解析漏洞、大小写可以绕过
 *   · 只有 ② → 在图片末尾追加 PHP 代码（图片马）能通过 getimagesize，
 *              如果目录还能解析 PHP，配合文件包含漏洞依然能执行
 *   · 只有 ③ → 文件名安全了，但内容还是可执行脚本
 *   · 只有 ④ → 目录不解析了，但上传的文件仍可能被其他方式利用
 *
 * 前三条是「让别人传不进来可执行内容」，第四条是「就算传进来了也执行不了」——
 * 前者是收敛攻击面，后者是兜底。**安全设计里兜底永远不能省。**
 *
 * ⚠️ 注意：本项目的运行环境是 PHP 内置服务器（`php -S`），
 *     它不支持 .htaccess，所以第 ④ 层在本靶场里无法真实生效 ——
 *     这一点在页面下方有说明。真实部署时它是最重要的一层。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

const UPLOAD_DIR = __DIR__ . '/../uploads';
const UPLOAD_URL = '/uploads';

if (!is_dir(UPLOAD_DIR)) {
    @mkdir(UPLOAD_DIR, 0777, true);
}

/** 第 ① 层：后缀白名单 */
const ALLOWED_EXT = ['jpg', 'jpeg', 'png', 'gif'];

/** 单文件大小上限（2 MB） */
const MAX_SIZE = 2 * 1024 * 1024;

$result = null;
$error = '';
$rejected = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $originalName = (string) $file['name'];
    $tmpPath = (string) $file['tmp_name'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        $error = '上传失败，错误码：' . $file['error'];
    } elseif ($file['size'] > MAX_SIZE) {
        $error = '文件过大（上限 ' . (MAX_SIZE / 1024 / 1024) . ' MB）';
    } else {
        // --------------------------------------------------------------
        // 第 ① 层：后缀白名单
        //
        // 必须 strtolower —— 否则 SHELL.PHP 能绕过（Windows 上尤其危险，
        // 因为文件系统本身不区分大小写）。
        // 必须用白名单而不是黑名单 —— 你怎么知道该禁哪些后缀？
        // 光 PHP 就有 .php .php3 .php4 .php5 .php7 .phtml .pht .phps .inc …
        // --------------------------------------------------------------
        $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if (!in_array($ext, ALLOWED_EXT, true)) {
            $rejected[] = "后缀 .{$ext} 不在白名单内";
        }

        // --------------------------------------------------------------
        // 第 ② 层：内容真实性检查
        //
        // getimagesize 会解析文件头，能挡住「改个后缀就说是图片」的情况。
        // 但它挡不住「图片马」（在合法图片末尾追加 PHP 代码）——
        // 所以这一层不能单独用，必须配合第 ④ 层。
        // --------------------------------------------------------------
        $imageInfo = @getimagesize($tmpPath);
        if ($imageInfo === false) {
            $rejected[] = '文件内容不是有效的图片（getimagesize 解析失败）';
        }

        if ($rejected) {
            $error = '上传被拒绝：' . implode('；', $rejected);
        } else {
            // ----------------------------------------------------------
            // 第 ③ 层：重命名
            //
            // 不让用户控制文件名。这样即使后缀校验被绕过，
            // 攻击者也无法指定一个「能被解析为脚本」的后缀。
            // 用 random_bytes 而不是 uniqid/时间戳 —— 后者可预测，
            // 攻击者能猜到文件名（这本身也是一类漏洞）。
            // ----------------------------------------------------------
            $safeName = bin2hex(random_bytes(8)) . '.' . $ext;

            if (move_uploaded_file($tmpPath, UPLOAD_DIR . '/' . $safeName)) {
                $result = [
                    'original' => $originalName,
                    'saved'    => $safeName,
                    'size'     => (int) $file['size'],
                    'type'     => $imageInfo['mime'] ?? '',
                    'width'    => $imageInfo[0] ?? 0,
                    'height'   => $imageInfo[1] ?? 0,
                    'url'      => UPLOAD_URL . '/' . $safeName,
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

/** 被拒绝的尝试记录（用于展示对照效果） */
$attackSamples = [
    'shell.php' => '直接传 PHP 脚本',
    'shell.PHP' => '大写后缀（绕过不做 strtolower 的校验）',
    'shell.php.jpg' => '双后缀（利用解析漏洞）',
    'shell.phtml' => '换一个 PHP 后缀',
];
?>
<?php layout_header(
    '文件上传 · 难度 high（已修复）',
    '白名单后缀 + 内容检查 + 重命名 + 目录禁执行 —— 四层叠加。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护：四层叠加</h3>
  <div class="tbl-wrap" style="margin-top:10px">
    <table>
      <thead><tr><th style="width:24%">层</th><th style="width:30%">手段</th><th>挡住了什么</th></tr></thead>
      <tbody>
        <tr>
          <td><b>① 后缀</b></td>
          <td><code>白名单 + strtolower</code></td>
          <td>非图片后缀；大小写绕过</td>
        </tr>
        <tr>
          <td><b>② 内容</b></td>
          <td><code>getimagesize</code></td>
          <td>改后缀伪装成图片的文件</td>
        </tr>
        <tr>
          <td><b>③ 重命名</b></td>
          <td><code>random_bytes(8)</code></td>
          <td>攻击者控制文件名与后缀</td>
        </tr>
        <tr>
          <td><b>④ 禁执行</b></td>
          <td>Web 服务器配置</td>
          <td><b>兜底</b>：即使前三层全被绕过，脚本也执行不了</td>
        </tr>
      </tbody>
    </table>
  </div>

  <h3>关键代码</h3>
  <pre style="margin:0">$ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));   <span class="c">// ①</span>
if (!in_array($ext, ALLOWED_EXT, true))              { <span class="c">/* 拒绝 */</span> }

if (@getimagesize($tmpPath) === false)               { <span class="c">/* 拒绝 */</span> }   <span class="c">// ②</span>

$safeName = bin2hex(random_bytes(8)) . '.' . $ext;                <span class="c">// ③</span></pre>
</div>

<div class="card">
  <form method="post" action="high.php" enctype="multipart/form-data">
    <div class="row">
      <input type="file" name="file" style="flex:1;min-width:240px">
      <button type="submit">上传</button>
    </div>
  </form>
  <p class="hint">
    把 low / medium 档成功的脚本传进来试试 —— 会被 ①② 层拦下。
  </p>
</div>

<?php if ($error !== ''): ?>
  <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
    <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
  </div>
<?php endif; ?>

<?php if ($result !== null): ?>
  <div class="card tight" style="background:var(--ok-soft);border-color:#a7f3d0">
    <div style="font-size:13px;color:#065f46;margin-bottom:8px">上传成功（合法图片）</div>
    <div class="kv"><b>原始文件名</b><span class="mono"><?= htmlspecialchars($result['original']) ?></span></div>
    <div class="kv"><b>实际保存为</b><span class="mono"><?= htmlspecialchars($result['saved']) ?></span></div>
    <div class="kv"><b>真实类型</b><span class="mono"><?= htmlspecialchars($result['type']) ?>
        · <?= (int) $result['width'] ?>×<?= (int) $result['height'] ?></span></div>
    <div class="kv"><b>大小</b><span class="mono"><?= $result['size'] ?> 字节</span></div>
    <div class="kv"><b>可访问地址</b>
      <a class="mono" href="<?= htmlspecialchars($result['url']) ?>" target="_blank">
        <?= htmlspecialchars($result['url']) ?>
      </a>
    </div>
  </div>
  <?php render_code_board(
      '注意实际保存的文件名',
      "你上传时用的名字: {$result['original']}\n"
      . "最终保存的名字:   {$result['saved']}\n\n"
      . "服务端【没有使用】你提供的文件名。\n"
      . "所以即使前面所有校验都被绕过，你也无法让文件带上 .php 后缀。"
  ); ?>
<?php endif; ?>

<h2>对照实验：同一批文件名，三档的结果</h2>
<p class="sub" style="margin-bottom:12px">
  下面这些文件名在 low 档全部能上传成功，在 high 档全部被 ① 层拦下。
</p>
<div class="tbl-wrap">
  <table>
    <thead><tr>
      <th style="width:34%">文件名</th>
      <th style="width:28%">绕过的是什么</th>
      <th>high 档结果</th>
    </tr></thead>
    <tbody>
      <?php foreach ($attackSamples as $name => $note): ?>
        <tr>
          <td class="mono"><?= htmlspecialchars($name) ?></td>
          <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          <td><span class="tag high">后缀白名单拒绝</span></td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="card" style="margin-top:20px">
  <h3 style="margin-top:0">第 ④ 层：目录禁止执行（真实部署配置）</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    <b>本靶场跑在 PHP 内置服务器上，不支持 .htaccess，所以这一层在这里无法真实生效。</b>
    但它是真实部署中最重要的一层，因为它是唯一能兜住「前三层同时被绕过」的手段。
  </p>
  <p style="margin:0 0 6px;font-size:13px;color:var(--muted)">Nginx：</p>
  <pre style="margin:0 0 10px">location ^~ /uploads/ {
    location ~ \.(php|php5|phtml|phar)$ { deny all; }
    # 或者更彻底：整个目录只当静态资源
    # add_header Content-Type application/octet-stream;
}</pre>
  <p style="margin:0 0 6px;font-size:13px;color:var(--muted)">Apache（upload 目录下放 .htaccess）：</p>
  <pre style="margin:0 0 10px">php_flag engine off
RemoveHandler .php .phtml .php5
AddType text/plain .php .phtml .php5</pre>
  <p style="margin:0;font-size:13px;color:var(--muted)">
    更彻底的做法：<b>把上传目录放到 Web 根之外</b>，通过应用层做鉴权后读取文件。
    这样连"能不能访问到"都不由文件系统决定。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">修复要点总结（面试会问的部分）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>后缀用白名单，不用黑名单。</b>
      黑名单永远列不全（.php / .php3 / .php4 / .php5 / .php7 / .phtml / .pht / .phps / .inc …），
      且不同 Web 服务器、不同配置下哪些后缀会被解析还不一样。
    </li>
    <li>
      <b>必须 strtolower。</b>
      在 Windows 这类不区分大小写的文件系统上，不转换大小写的后缀校验形同虚设。
    </li>
    <li>
      <b>内容检查不能只看后缀，也不能只看 Content-Type。</b>
      <code>$_FILES['file']['type']</code> 完全由客户端控制；
      <code>getimagesize</code> 能挡伪装但挡不住图片马，必须配合目录禁执行。
    </li>
    <li>
      <b>重命名要够随机。</b>
      <code>uniqid()</code> / <code>time()</code> 可预测 —— 攻击者能猜到文件名，
      这本身就是一类漏洞（可导致越权访问他人上传的文件）。
    </li>
    <li>
      <b>上传目录必须禁止执行脚本。</b>
      这是唯一能兜住其他层失效的手段，不能省。
    </li>
    <li>
      <b>其他：</b>限制大小、限制数量、校验文件头、图片二次处理（重新编码可以彻底销毁图片马）、
      上传目录独立域名（Cookie 隔离）。
    </li>
  </ul>
</div>

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

<?php layout_footer(); ?>
