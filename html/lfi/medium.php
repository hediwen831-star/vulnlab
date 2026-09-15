<?php
/**
 * 文件包含 · medium 档
 *
 * 漏洞成因：用**字符串黑名单**过滤路径穿越与危险协议。
 *
 * 这里的黑名单看起来挺全：`../`、`php://`、`http://` 都堵了。
 * 但有两个经典绕过：
 *
 *   ① **双写**：`str_replace('../', '', '....//')` → 得到 `../`
 *      （因为 `....//` 里只有一处 `../` 匹配，删掉后剩下的正好拼回来）
 *
 *   ② **大小写**：用的是区分大小写的 `str_replace`，
 *      而 PHP 的伪协议名**不区分大小写** —— `PHP://filter` 照样能用
 *
 * 这两个绕过和 SQL 注入里的「双写绕过」是同一个机制：
 * **过滤只扫一遍，而拼接是可以把危险片段重新拼回来的。**
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
$blockedBy = '';
$lastPath = '';

if ($submitted) {
    // ------------------------------------------------------------------
    // 漏洞点：黑名单 + 单次替换
    //
    // 只堵了「向上退目录」的两种写法。
    // 而 str_replace 是**单次替换** —— 这给了「双写」一条路。
    //
    // 顺带一提：本档没有过滤伪协议，但由于路径前面固定拼了 `pages/`，
    // 伪协议用不了（`php://` 必须在路径开头）。所以这里也不需要对它设防 ——
    // 「固定前缀」本身就顺带挡住了一类攻击面，这是它唯一的意外好处。
    // ------------------------------------------------------------------
    $blacklist = ['../', '..\\'];
    $filtered = $page;

    foreach ($blacklist as $bad) {
        if (strpos($filtered, $bad) !== false) {
            $blockedBy = $bad;
            $filtered = str_replace($bad, '', $filtered);
        }
    }

    $lastPath = __DIR__ . '/pages/' . $filtered;

    ob_start();
    try {
        include $lastPath;
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
    $included = (string) ob_get_clean();

    if ($included === '' && $error === '') {
        $error = '包含失败：文件不存在或内容为空。';
    }
}

/** 绕过示例 */
$bypasses = [
    '....//....//config.php' => '★ 双写：删掉中间的 `../` 之后，剩下的正好拼回 `../`',
    '....//....//....//config.php' => '写更多层（需要穿越更深时用）',
    '../../config.php'       => '对照组：会被拦下',
    '..%2f..%2fconfig.php'   => '对照组：$_GET 会自动解码，到过滤器手里还是明文 `../`',
];
?>
<?php layout_header(
    '文件包含 · 难度 medium',
    '黑名单 + 单次替换 —— 而「单次替换」本身就是一个绕过点。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$blacklist = [<span class="s">'../'</span>, <span class="s">'..\\'</span>, <span class="s">'php://'</span>, <span class="s">'http://'</span>, ...];

foreach ($blacklist as $bad) {
    if (strpos($filtered, $bad) !== false) {
        $filtered = str_replace($bad, <span class="s">''</span>, $filtered);   <span class="c">// ← 单次替换</span>
    }
}</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    和 low 档一样读到 <code>pages/</code> 之外的文件，但这次不能直接写 <code>../</code>。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="medium.php">
    <input type="text" name="page" value="<?= htmlspecialchars($page) ?>"
           placeholder="about" style="min-width:400px">
    <button type="submit">加载</button>
  </form>
</div>

<?php if ($blockedBy !== ''): ?>
  <div class="card tight" style="background:var(--warn-soft);border-color:#fde68a;margin-bottom:14px">
    <div style="font-size:13px;color:#92400e;margin-bottom:8px">过滤器命中</div>
    <div class="kv"><b>命中的词</b><span class="mono"><?= htmlspecialchars($blockedBy) ?></span></div>
    <div class="kv"><b>过滤前</b><span class="mono"><?= htmlspecialchars($page) ?></span></div>
    <div class="kv"><b>过滤后（实际用于拼接）</b><span class="mono"><?= htmlspecialchars($page) ?></span></div>
    <p style="margin:8px 0 0;font-size:13px;color:#92400e">
      注意三行的差异 —— <b>它删掉了匹配到的片段，然后拿剩下的去拼接</b>。
      「删掉之后会变成什么」就是绕过的空间。
    </p>
  </div>
<?php endif; ?>

<?php if ($submitted): ?>
  <?php
  render_code_board('服务端实际尝试包含的路径', $lastPath);
  ?>
  <?php if ($error !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
    </div>
  <?php endif; ?>
  <?php if ($included !== ''): ?>
    <div class="card">
      <h3 style="margin-top:0">包含结果</h3>
      <div style="border:1px dashed var(--line);border-radius:8px;padding:14px;background:#fff;word-break:break-all">
        <?= $included ?>
      </div>
    </div>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">核心绕过点：双写</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:34%">输入</th><th style="width:32%">过滤后</th><th>结果</th></tr></thead>
      <tbody>
        <tr>
          <td class="mono">....//....//config.php</td>
          <td class="mono">../../config.php</td>
          <td><b style="color:var(--ok)">穿越成功</b></td>
        </tr>
        <tr>
          <td class="mono">../../config.php</td>
          <td class="mono">config.php</td>
          <td><span style="color:var(--danger)">被拦（退不回上级目录）</span></td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="hint">
    <b>这不是巧合，而是「删除型过滤」的通病：</b><br>
    你删掉匹配到的片段之后，<b>剩下的字符有可能重新拼出那个片段</b>。<br>
    这和 SQL 注入里的 <code>ununionion</code>（删掉 <code>union</code> 后拼回 <code>union</code>）
    是同一个机制 —— 只不过这里拼回的是路径分隔符。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">可用载荷</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:58%">载荷</th><th>说明</th></tr></thead>
      <tbody>
        <?php foreach ($bypasses as $payload => $note): ?>
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
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>过滤器删掉了哪些词？<b>删掉之后，剩下的字符会拼成什么？</b></li>
    <li>黑名单里的 <code>php://</code> 是小写 —— 那 <code>PHP://</code> 呢？</li>
    <li>如果不过滤 <code>../</code> 而是直接给一个绝对路径，还需要穿越吗？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/lfi.md</code>。</p>
</div>

<?php layout_footer(); ?>
