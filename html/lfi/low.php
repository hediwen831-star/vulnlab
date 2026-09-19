<?php
/**
 * 文件包含 · low 档
 *
 * 漏洞成因：把用户输入直接拼进 `include`，且**不做任何路径限制**。
 *
 * 文件包含之所以危险，是因为 `include` 干的事是「把指定文件的内容读进来
 * **当作 PHP 代码执行**」—— 它同时具备两个能力：
 *
 *   ① 读文件（哪怕文件在 Web 根之外）
 *   ② 执行代码（只要文件内容是 PHP）
 *
 * 这比单纯的「任意文件读取」高一个量级：后者只能拿到数据，
 * 前者能直接拿到代码执行。而两个能力叠加就构成了 getshell 的完整路径。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$page = isset($_GET['page']) ? (string) $_GET['page'] : '';
$submitted = ($page !== '');

$included = '';
$error = '';
$sourcePreview = '';
$elapsed = 0.0;

if ($submitted) {
    // ------------------------------------------------------------------
    // 漏洞点：直接拼进 include，没有任何过滤
    //
    // 注意这里【连后缀都没拼】—— 就是把用户给的值原样当路径。
    // 这是最"干净"的漏洞形态：攻击者可以控制完整路径。
    // ------------------------------------------------------------------
    $fullPath = __DIR__ . '/pages/' . $page;

    $started = microtime(true);
    ob_start();
    try {
        @include $fullPath;
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
    $included = (string) ob_get_clean();
    $elapsed = microtime(true) - $started;

    if ($included === '' && $error === '') {
        $error = '包含失败：文件不存在或内容为空。';
    }
}

/** 演示载荷
 *
 * ⚠️ 注意本档的拼接方式是 `__DIR__ . '/pages/' . $page` —— **前缀固定**。
 *
 * 这带来一个真实存在的限制：**PHP 伪协议用不了**。
 * 因为 `php://` 必须在路径的最开头才会被识别成协议，
 * 而这里前面被拼上了 `<绝对路径>/pages/`。
 *
 * 这不是我写错了 —— 真实的 LFI 大多就是这个形态（前缀写死、只控制后半段）。
 * 能完整控制路径的写法（`include $_GET['page']`）反而少见，也更危险 ——
 * 那种形态下伪协议、绝对路径、任意穿越全都可用。
 */
$samples = [
    'about.php'      => '正常页面（对照组）',
    'contact.php'    => '正常页面（对照组）',
    '../../config.php'            => '★ 路径穿越：读靶场配置（它会被当 PHP 执行）',
    '../../../../Windows/win.ini' => '★ 路径穿越到系统目录（Windows）',
    '..%2f..%2fconfig.php'        => 'URL 编码的穿越（看服务端在解码前还是解码后拼接）',
    '/etc/passwd'    => '绝对路径（这里同样被前缀挡住，Linux 上可试）',
];
?>
<?php layout_header(
    '文件包含 · 难度 low',
    'include 直接吃用户输入 —— 它既能读文件，又能执行代码。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">零防护 —— 直接拼接：</p>
  <pre style="margin:10px 0 0">$fullPath = <span class="s">__DIR__ . '/pages/'</span> . $page;
include $fullPath;</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    读到一个 <b>pages 目录之外</b>的文件。
    能做到这一点，就说明路径穿越成立 —— 而路径穿越是 LFI 的核心。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="low.php">
    <input type="text" name="page" value="<?= htmlspecialchars($page) ?>"
           placeholder="about" style="min-width:400px">
    <button type="submit">加载</button>
  </form>
  <p class="hint">
    服务端会 <code>include</code> 你给的值（前面拼了 <code>pages/</code>）。
  </p>
</div>

<?php if ($submitted): ?>
  <?php
  render_code_board(
      '服务端实际尝试包含的路径',
      $fullPath . "\n\n"
      . "你的输入: {$page}\n"
      . "拼接结果: __DIR__ . '/pages/' . '{$page}'\n\n"
      . "注意：include 会把文件内容【当 PHP 代码执行】，\n"
      . "所以如果读到的是 PHP 文件，它会先被解析再输出。"
  );
  ?>

  <?php if ($error !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
    </div>
  <?php endif; ?>

  <?php if ($included !== ''): ?>
    <div class="card">
      <h3 style="margin-top:0">包含结果（渲染后的输出）</h3>
      <div style="border:1px dashed var(--line);border-radius:8px;padding:14px;background:#fff">
        <?= $included ?>
      </div>
      <p class="hint">耗时 <?= number_format($elapsed, 4) ?> 秒</p>
    </div>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">可用载荷</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:56%">载荷</th><th>说明</th></tr></thead>
      <tbody>
        <?php foreach ($samples as $payload => $note): ?>
          <tr>
            <td class="mono" style="word-break:break-all">
              <a href="?page=<?= rawurlencode($payload) ?>"><?= htmlspecialchars($payload) ?></a>
            </td>
            <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>

<div class="card">
  <h3 style="margin-top:0">为什么 LFI 比「任意文件读取」更危险</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:28%">能力</th><th>后果</th></tr></thead>
      <tbody>
        <tr>
          <td><b>读文件</b></td>
          <td>能读到 Web 根之外的内容 —— 配置文件、私钥、系统文件</td>
        </tr>
        <tr>
          <td><b>执行代码</b></td>
          <td>
            <code>include</code> 会把内容当 PHP 解析。
            配合「文件上传」（传一个图片马）+ LFI（包含它）＝ <b>getshell</b>
          </td>
        </tr>
        <tr>
          <td><b>用伪协议</b></td>
          <td>
            <code>php://filter</code> 能把源码 base64 编码后读出来 ——
            这样就读到了「未经 PHP 解析的原始源码」，能直接找里面的密钥和后续漏洞
          </td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="hint">
    第二条尤其值得注意：<b>它和本靶场的「文件上传」场景构成完整的攻击链</b> ——
    上传马 → LFI 包含它 → 代码执行。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>服务端拼出来的路径，你能控制到哪一部分？</li>
    <li>用什么符号可以「往上退一级目录」？</li>
    <li>除了真实文件路径，<code>include</code> 还能接受什么形式的目标？（提示：PHP 伪协议）</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/lfi.md</code>。</p>
</div>

<?php layout_footer(); ?>
