<?php
/**
 * 文件包含 · high 档 —— 修复对照
 *
 * 修复方式：**白名单映射表**。
 *
 * 这是文件包含最彻底、也最省心的修复方式，原因有三：
 *
 *   ① **从根上消除路径拼接** —— 用户给的值只用来「查表」，
 *      查到的值是代码里写死的常量，用户无法影响最终路径
 *
 *   ② **不需要考虑任何变形** —— `../`、`....//`、大小写、编码、
 *      绝对路径、各种伪协议……全都不再需要枚举。
 *      因为攻击者的输入**根本没有进入路径**
 *
 *   ③ **可读性强** —— 看代码就知道这个页面能加载哪些文件，
 *      不需要在脑子里模拟过滤器的行为
 *
 * ══════════════════════════════════════════════════════════════════
 * 为什么白名单在这里是「唯一正确」的选择
 * ══════════════════════════════════════════════════════════════════
 *
 * 前两档的失败模式值得对照着看：
 *
 *   low    ：完全拼接 —— 攻击者控制完整路径
 *   medium ：黑名单 —— 试图枚举「危险的路径写法」
 *
 * 而 medium 的困难在于：**「危险路径」的写法是无穷的**。
 * 相对路径、绝对路径、各种编码、PHP 支持的十几个伪协议、
 * 不同操作系统的路径分隔符……黑名单永远列不全。
 *
 * 但换到白名单视角，问题瞬间变简单了：
 * **这个页面本来就只应该加载那三个文件，别的都不该被加载。**
 *
 * 所以不是「想办法过滤掉坏的」，而是「只允许好的」——
 * 这就是白名单相对黑名单的本质优势。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$page = isset($_GET['page']) ? (string) $_GET['page'] : '';
$submitted = ($page !== '');

$included = '';
$error = '';
$audit = [];
$resolvedPath = '';

// ------------------------------------------------------------------
// 修复点：白名单映射表
//
// 用户提供的值只作为【查表的键】，不作为路径的一部分。
// 查到了就用代码里写死的文件名，查不到就拒绝。
// ------------------------------------------------------------------
const ALLOWED_PAGES = [
    'about'   => 'about.php',
    'contact' => 'contact.php',
    'help'    => 'help.php',
];

if ($submitted) {
    if (!isset(ALLOWED_PAGES[$page])) {
        $error = "页面「{$page}」不在白名单内。";
        $audit[] = ['① 白名单校验', $page, '✗ 拒绝'];
    } else {
        $audit[] = ['① 白名单校验', $page, '✓ 通过'];

        // 路径由常量拼成 —— 用户输入没有参与
        $resolvedPath = __DIR__ . '/pages/' . ALLOWED_PAGES[$page];
        $audit[] = ['② 路径解析', ALLOWED_PAGES[$page] . ' → ' . basename($resolvedPath),
                    '✓ 值为代码常量，用户无法影响'];

        // 兜底：即使有人把映射表改坏，也确保最终路径仍在 pages/ 之内
        //
        // 注意这里用 strpos(...) === 0 而不是 str_starts_with() ——
        // 后者是 PHP 8.0 才引入的，靶场声明兼容 7.2+。
        // （这个坑我在项目里已经踩过两次了，所以 verify_lab.py 里加了一条
        //   静态检查专门扫这类函数。）
        $realBase = realpath(__DIR__ . '/pages');
        $realTarget = realpath($resolvedPath);
        $insideBase = $realBase !== false
            && $realTarget !== false
            && strpos($realTarget, $realBase . DIRECTORY_SEPARATOR) === 0;

        if (!$insideBase) {
            $error = '路径越界，已阻止。';
            $audit[] = ['③ 越界兜底', $resolvedPath, '✗ 目标不在 pages/ 内'];
        } else {
            $audit[] = ['③ 越界兜底', $resolvedPath, '✓ 确认在 pages/ 目录内'];

            ob_start();
            include $resolvedPath;
            $included = (string) ob_get_clean();
        }
    }
}

/** 攻击载荷对照（本档用白名单映射，正常请求写键名即可） */
$attacks = [
    '../../config.php'          => '路径穿越',
    '....//....//config.php'    => '双写绕过',
    '..%2f..%2fconfig.php'      => 'URL 编码',
    '/etc/passwd'               => '绝对路径',
    'php://filter/convert.base64-encode/resource=pages/about.php' => '伪协议（本档被前缀挡住，但白名单也一并拦住）',
    'about'                     => '正常请求（对照组 —— 白名单里存的是键名）',
];
?>
<?php layout_header(
    '文件包含 · 难度 high（已修复）',
    '白名单映射表 —— 用户输入只用来查表，不参与路径拼接。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护：白名单映射</h3>
  <pre style="margin:10px 0 0;background:#064e3b">const ALLOWED_PAGES = [
    <span class="s">'about'</span>   =&gt; <span class="s">'about.php'</span>,
    <span class="s">'contact'</span> =&gt; <span class="s">'contact.php'</span>,
    <span class="s">'help'</span>    =&gt; <span class="s">'help.php'</span>,
];

if (!isset(ALLOWED_PAGES[$page])) { <span class="c">/* 拒绝 */</span> }
include __DIR__ . <span class="s">'/pages/'</span> . ALLOWED_PAGES[$page];   <span class="c">// 值是常量</span></pre>

  <p style="margin:10px 0 0;font-size:14px;color:#065f46">
    关键点：<b>用户输入只被当作「键」来查表</b>，
    真正进入路径的是表里写死的常量值 —— 攻击者无法影响它。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="high.php">
    <input type="text" name="page" value="<?= htmlspecialchars($page) ?>"
           placeholder="about / contact / help" style="min-width:400px">
    <button type="submit">加载</button>
  </form>
  <p class="hint">允许的值：<code>about</code>、<code>contact</code>、<code>help</code></p>
</div>

<?php if ($submitted): ?>
  <div class="card tight" style="margin-bottom:14px">
    <div style="font-size:13px;color:var(--muted);margin-bottom:10px">校验过程（逐层审计）</div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th style="width:24%">层</th><th style="width:52%">观察到的值</th><th>结果</th></tr></thead>
        <tbody>
          <?php foreach ($audit as [$layer, $value, $result]): ?>
            <tr>
              <td><?= htmlspecialchars($layer) ?></td>
              <td class="mono" style="word-break:break-all"><?= htmlspecialchars($value) ?></td>
              <td style="color:<?= strpos($result, '✗') === 0 ? 'var(--danger)' : 'var(--ok)' ?>;font-weight:500">
                <?= htmlspecialchars($result) ?>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>

  <?php if ($error !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
      <p style="margin:8px 0 0;font-size:14px;color:#b91c1c">
        注意上面：<b>用户输入根本没有进入路径拼接</b> ——
        它只是一个查表的键，查不到就直接结束，连路径都不会被构造出来。
      </p>
    </div>
  <?php endif; ?>

  <?php if ($included !== ''): ?>
    <div class="card">
      <h3 style="margin-top:0">包含结果</h3>
      <div style="border:1px dashed var(--line);border-radius:8px;padding:14px;background:#fff">
        <?= $included ?>
      </div>
    </div>
  <?php endif; ?>
<?php endif; ?>

<h2>对照实验：同一批载荷，三档的结果</h2>
<p class="sub" style="margin-bottom:12px">
  low 档全部得手，medium 档大部分得手，high 档全部被拦。
</p>
<div class="tbl-wrap">
  <table>
    <thead><tr>
      <th style="width:46%">载荷</th>
      <th style="width:26%">绕过的防线</th>
      <th>high 档结果</th>
    </tr></thead>
    <tbody>
      <?php foreach ($attacks as $attack => $note): ?>
        <tr>
          <td class="mono" style="word-break:break-all">
            <a href="?page=<?= rawurlencode($attack) ?>"><?= htmlspecialchars($attack) ?></a>
          </td>
          <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          <td>
            <?php if ($attack === 'about'): ?>
              <span class="tag" style="background:var(--ok-soft);color:var(--ok)">正常加载</span>
            <?php else: ?>
              <span class="tag high">白名单拒绝</span>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="card" style="margin-top:20px">
  <h3 style="margin-top:0">为什么白名单在这里是唯一正确的选择</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    回顾前两档的失败模式：
  </p>
  <pre style="margin:0 0 12px">low    ：完全拼接 —— 攻击者控制完整路径
medium ：黑名单 —— 试图枚举「危险的路径写法」，但那是无穷集合

  相对路径 ../    绝对路径 /etc/passwd
  URL 编码 %2e%2e%2f
  双写 ....//
  大小写 PHP://
  十几个 PHP 伪协议：php:// file:// data:// expect:// phar:// zip:// ...
  Windows / Linux 的路径分隔符差异
  ...</pre>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    而换成白名单视角，问题瞬间简单了：<br>
    <b>这个页面本来就只该加载那三个文件 —— 别的都不该被加载。</b>
  </p>
  <p class="margin:10px 0 0;font-size:14px;color:var(--muted)">
    所以修复思路不是「想办法过滤掉坏的」，而是「只允许好的」。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">修复要点总结</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>能用白名单就用白名单。</b>
      包含的页面通常是有限集合，映射表是最直接的做法。
    </li>
    <li>
      <b>不要依赖黑名单过滤路径。</b>
      危险写法是无穷的（相对/绝对/编码/伪协议/平台差异），列不全。
    </li>
    <li>
      <b>真要拼接时，用 <code>basename()</code> 剥掉目录部分</b> ——
      这样即使输入含路径分隔符，也只会得到文件名。
    </li>
    <li>
      <b>用完 <code>realpath()</code> 做越界兜底。</b>
      本档的第 ③ 层就是这个 —— 即使白名单表被人改坏，也还有一道检查。
    </li>
    <li>
      <b>禁止伪协议。</b>
      <code>allow_url_include = Off</code>（PHP 默认就是 Off），
      但 <code>php://filter</code> 不受它限制，所以不能只靠这个配置。
    </li>
    <li>
      <b>注意和文件上传的组合风险。</b>
      上传目录如果可被包含，就能 getshell ——
      所以上传目录不仅要禁止执行，也应该禁止被 include。
    </li>
  </ul>
</div>

<?php layout_footer(); ?>
