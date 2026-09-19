<?php
/**
 * 页面布局组件。
 *
 * 一个靶场「看起来是不是正经项目」，八成取决于它的 UI。
 * 大部分学生做的靶场是裸 HTML 表格，这个文件存在的唯一目的就是
 * 让 VulnLab 看起来像 2026 年的东西 —— 而这本来就是加分项。
 */

declare(strict_types=1);

/**
 * 输出页面头部。
 *
 * @param string $title    页面标题
 * @param string $subtitle 副标题
 */
function layout_header(string $title, string $subtitle = ''): void
{
    // 从 SCRIPT_NAME 推断当前页面所属模块，用于导航高亮。
    // 不依赖具体文件名，所以新增 low/medium/high 各档不用改这里。
    $script = $_SERVER['SCRIPT_NAME'] ?? '/index.php';

    /** 导航项：模块目录 => 显示名 */
    $navModules = [
        'sqli'        => 'SQL 注入',
        'xss'         => 'XSS',
        'upload'      => '文件上传',
        'ssrf'        => 'SSRF',
        'cmdi'        => '命令注入',
        'lfi'         => '文件包含',
        'unserialize' => 'PHP 反序列化',
        'xxe'         => 'XXE',
        'jwt'         => 'JWT',
        'csrf'        => 'CSRF',
        'ssti'        => 'SSTI',
        'idor'        => '越权',
    ];

    $currentModule = 'index';
    foreach (array_keys($navModules) as $module) {
        if (strpos($script, "/{$module}/") !== false) {
            $currentModule = $module;
            break;
        }
    }

    // 「查看源码」链接指向当前页面自身；index 页则指向 index.php
    $sourceFile = ltrim(str_replace('\\', '/', $script), '/');
    if ($sourceFile === '') {
        $sourceFile = 'index.php';
    }
    ?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars($title) ?> · <?= SITE_NAME ?></title>
<style>
:root{
  --bg:#f7f8fa; --card:#ffffff; --line:#e5e7eb; --line-soft:#f0f1f4;
  --text:#1f2328; --muted:#6b7280; --dim:#9ca3af;
  --accent:#2563eb; --accent-soft:#eff6ff;
  --danger:#dc2626; --danger-soft:#fef2f2;
  --warn:#d97706; --warn-soft:#fffbeb;
  --ok:#059669; --ok-soft:#ecfdf5;
  --mono:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--bg); color:var(--text);
  font:15px/1.65 -apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;
  -webkit-font-smoothing:antialiased;
}
.wrap{max-width:960px;margin:0 auto;padding:32px 24px 64px}
header.site{background:var(--card);border-bottom:1px solid var(--line);padding:14px 0}
header.site .wrap{padding:0 24px;display:flex;align-items:center;gap:24px;flex-wrap:wrap}
.brand{font-weight:600;font-size:16px;letter-spacing:-.01em;text-decoration:none;color:var(--text)}
.brand span{color:var(--accent)}
nav.top{display:flex;gap:4px;font-size:14px}
nav.top a{
  color:var(--muted);text-decoration:none;padding:6px 12px;
  border-radius:8px;transition:background .12s,color .12s
}
nav.top a:hover{background:var(--line-soft);color:var(--text)}
nav.top a.on{background:var(--accent-soft);color:var(--accent);font-weight:500}
.warnbar{
  background:var(--warn-soft);border:1px solid #fde68a;color:#92400e;
  padding:10px 16px;border-radius:10px;font-size:13px;margin-bottom:24px
}
h1{font-size:24px;font-weight:600;letter-spacing:-.02em;margin:0 0 6px}
h2{font-size:17px;font-weight:600;margin:32px 0 12px;letter-spacing:-.01em}
h3{font-size:15px;font-weight:600;margin:20px 0 8px}
.sub{color:var(--muted);font-size:14px;margin:0 0 24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin-bottom:16px}
.card.tight{padding:16px 18px}
.grid{display:grid;gap:14px}
@media(min-width:640px){.grid.two{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(min-width:880px){.grid.three{grid-template-columns:repeat(3,minmax(0,1fr))}}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line-soft)}
th{color:var(--muted);font-weight:500;font-size:13px;background:#fafbfc}
tr:last-child td{border-bottom:none}
td.mono,code,.mono{font-family:var(--mono);font-size:13px}
code{background:var(--line-soft);padding:2px 6px;border-radius:5px;color:#0f172a}
pre{
  background:#0f172a;color:#e2e8f0;padding:16px 18px;border-radius:10px;
  overflow-x:auto;font-family:var(--mono);font-size:13px;line-height:1.6;margin:12px 0
}
pre .k{color:#7dd3fc} pre .s{color:#86efac} pre .c{color:#94a3b8} pre .v{color:#fca5a5}
a{color:var(--accent)}
.tag{
  display:inline-block;font-size:12px;padding:2px 9px;border-radius:999px;
  background:var(--line-soft);color:var(--muted);font-weight:500
}
.tag.low{background:var(--ok-soft);color:var(--ok)}
.tag.medium{background:var(--warn-soft);color:var(--warn)}
.tag.high{background:var(--danger-soft);color:var(--danger)}
.tag.info{background:var(--accent-soft);color:var(--accent)}
form.inline{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0}
input[type=text]{
  flex:1;min-width:200px;padding:9px 13px;border:1px solid var(--line);border-radius:8px;
  font-family:var(--mono);font-size:14px;background:#fff
}
input[type=text]:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
button{
  padding:9px 18px;border:1px solid var(--accent);background:var(--accent);color:#fff;
  border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;font-family:inherit
}
button:hover{filter:brightness(.94)}
button.ghost{background:#fff;color:var(--muted);border-color:var(--line)}
button.ghost:hover{background:var(--line-soft);color:var(--text)}
.links{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.links a{
  font-size:13px;text-decoration:none;padding:6px 12px;border-radius:8px;
  border:1px solid var(--line);background:#fff;color:var(--muted)
}
.links a:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-soft)}
.links a.cur{border-color:var(--accent);background:var(--accent-soft);color:var(--accent);font-weight:500}
.sqlbox{
  background:#0f172a;color:#cbd5e1;padding:14px 16px;border-radius:10px;
  font-family:var(--mono);font-size:13px;overflow-x:auto;white-space:pre-wrap;word-break:break-all
}
.sqlbox .kw{color:#fca5a5}
.sqlbox .lit{color:#86efac}
.empty{color:var(--dim);font-size:14px;padding:14px 0}
.hint{font-size:13px;color:var(--muted);margin-top:10px}
footer{color:var(--dim);font-size:13px;text-align:center;padding:32px 24px;border-top:1px solid var(--line);margin-top:40px}
.kv{display:flex;gap:10px;font-size:13px;padding:3px 0}
.kv b{color:var(--muted);font-weight:500;min-width:88px}
.flag{
  font-family:var(--mono);color:var(--danger);background:var(--danger-soft);
  padding:2px 8px;border-radius:6px;font-size:13px
}
</style>
</head>
<body>
<header class="site">
  <div class="wrap">
    <a class="brand" href="index.php">Vuln<span>Lab</span></a>
    <nav class="top">
      <a href="../index.php" class="<?= $currentModule === 'index' ? 'on' : '' ?>">漏洞矩阵</a>
      <?php foreach ($navModules as $module => $label): ?>
        <a href="../<?= $module ?>/low.php"
           class="<?= $currentModule === $module ? 'on' : '' ?>"><?= htmlspecialchars($label) ?></a>
      <?php endforeach; ?>
      <a href="../source.php?file=<?= htmlspecialchars($sourceFile) ?>">查看源码</a>
    </nav>
  </div>
</header>
<div class="wrap">
  <div class="warnbar">
    仅限本地 / 授权教学环境使用。禁止部署至公网，禁止用于任何未经授权的测试。
  </div>
  <h1><?= htmlspecialchars($title) ?></h1>
  <?php if ($subtitle !== ''): ?>
    <p class="sub"><?= $subtitle ?></p>
  <?php endif; ?>
<?php
}

/** 输出页面尾部。 */
function layout_footer(): void
{
    ?>
</div>
<footer>
  VulnLab · 自研漏洞靶场与 PoC 基准集 · 用于安全学习与扫描器效果评测
</footer>
</body>
</html>
<?php
}

/**
 * 渲染「执行了什么 SQL」的黑板。
 *
 * 这是靶场最重要的教学元素：不放 SQL 学生只能靠猜，
 * 放了 SQL 才能直观看到「参数拼接后语句变成了什么样」。
 */
function render_sql_board(string $sql): void
{
    ?>
    <div class="card tight">
      <div style="font-size:13px;color:var(--muted);margin-bottom:8px">
        服务端实际执行的语句
      </div>
      <div class="sqlbox"><?= highlight_sql($sql) ?></div>
    </div>
    <?php
}

/** 给 SQL 加一点语法着色（纯展示用途，非解析器）。 */
function highlight_sql(string $sql): string
{
    $escaped = htmlspecialchars($sql, ENT_QUOTES);
    $keywords = [
        'SELECT', 'FROM', 'WHERE', 'UNION', 'ALL', 'AND', 'OR', 'ORDER', 'BY',
        'LIMIT', 'OFFSET', 'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET',
        'DELETE', 'DROP', 'TABLE', 'GROUP', 'HAVING', 'NULL', 'AS',
    ];
    foreach ($keywords as $kw) {
        $escaped = preg_replace(
            '/\b' . $kw . '\b/i',
            '<span class="kw">' . $kw . '</span>',
            $escaped
        );
    }
    $escaped = preg_replace("/'([^']*)'/", "<span class=\"lit\">'$1'</span>", $escaped);
    return $escaped;
}

/**
 * 渲染通用的「代码黑板」。
 *
 * 与 render_sql_board 是同一个思路：把服务端的中间产物直接摊开给学生看。
 * SQL 场景看的是拼接后的语句，XSS 场景看的是拼接后的 HTML ——
 * 「输出点」和「输出内容」都可视化之后，漏洞成因就不需要解释了。
 *
 * @param string $label   黑板标题
 * @param string $content 要展示的内容（按原文展示，不解析）
 * @param string $empty   内容为空时的提示
 */
function render_code_board(string $label, string $content, string $empty = '(无内容)'): void
{
    ?>
    <div class="card tight" style="margin-bottom:14px">
      <div style="font-size:13px;color:var(--muted);margin-bottom:8px">
        <?= htmlspecialchars($label) ?>
      </div>
      <?php if ($content === ''): ?>
        <div class="empty" style="padding:8px 0"><?= htmlspecialchars($empty) ?></div>
      <?php else: ?>
        <pre style="margin:0"><?= htmlspecialchars($content) ?></pre>
      <?php endif; ?>
    </div>
    <?php
}

/**
 * 渲染「服务端输出」与「浏览器解析结果」的对照。
 *
 * 这是 XSS 场景的核心教学元素：同一段内容，作为源代码看是一回事，
 * 被浏览器解析后是另一回事。把两者并排放，学生能直观看到
 * 「转义」到底改变了什么。
 *
 * ⚠️ 注意：右侧是**故意不转义**地渲染用户输入的 —— 这正是漏洞本身。
 * 本文件是靶场，这个行为是设计的一部分，不是疏忽。
 */
function render_xss_compare(string $raw_output, string $charset = 'UTF-8'): void
{
    ?>
    <div class="card tight" style="margin-bottom:14px">
      <div style="display:grid;gap:14px;grid-template-columns:1fr">
        <div>
          <div style="font-size:13px;color:var(--muted);margin-bottom:6px">
            ① 服务端拼接出的 HTML（源代码视角，已转义展示）
          </div>
          <pre style="margin:0"><?= htmlspecialchars($raw_output) ?></pre>
        </div>
        <div>
          <div style="font-size:13px;color:var(--danger);margin-bottom:6px">
            ② 浏览器实际解析的结果（原始输出，未转义）
          </div>
          <div style="border:1px dashed #fecaca;border-radius:8px;padding:13px;background:#fff">
            <?= $raw_output /* 故意不转义：这就是漏洞点 */ ?>
          </div>
        </div>
      </div>
    </div>
    <?php
}

/**
 * 把系统命令的输出转义成可安全嵌入 HTML 的字符串。
 *
 * ⚠️ 这里踩过一个很隐蔽的坑，值得记下来：
 *
 *   Windows 上系统命令的输出默认是 **GBK 编码**（比如 ping 的「正在 Ping ...」）。
 *   如果直接把这段 GBK 文本丢给 `htmlspecialchars()`，
 *   而 PHP 的默认编码是 UTF-8 —— 那么它会遇到「非法 UTF-8 序列」。
 *
 *   关键在于：**`htmlspecialchars()` 遇到非法序列时会返回【空字符串】**，
 *   而不是跳过非法字节继续处理（除非传了 `ENT_SUBSTITUTE` 标志）。
 *
 *   结果是页面不报错、不告警，只是「命令输出那一栏莫名其妙是空的」——
 *   当时排查了很久才定位到。
 *
 * 所以这里做两件事：
 *   ① 先把 GBK 输出转成 UTF-8（有 mbstring 用 mb_convert_encoding，否则退到 iconv）
 *   ② 加 `ENT_SUBSTITUTE` 兜底：即使还有非法字节，也只是替换成占位符，
 *      而不是把整段输出清空
 *
 * 这和 XSS 场景 high 档里强调「ENT_SUBSTITUTE 不能省」是同一件事 ——
 * 只不过那次是从"构造恶意输入"的角度讲，这次是真实踩到了。
 */
function command_output_html(string $output): string
{
    if ($output === '') {
        return '(无输出)';
    }

    if (stripos(PHP_OS_FAMILY, 'Windows') !== false) {
        if (function_exists('mb_convert_encoding')) {
            $converted = @mb_convert_encoding($output, 'UTF-8', 'GBK');
            if (is_string($converted) && $converted !== '') {
                $output = $converted;
            }
        } elseif (function_exists('iconv')) {
            $converted = @iconv('GBK', 'UTF-8//IGNORE', $output);
            if (is_string($converted) && $converted !== '') {
                $output = $converted;
            }
        }
    }

    return htmlspecialchars($output, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * 渲染用户结果表。 */
function render_users_table(array $rows): void
{
    if (empty($rows)) {
        echo '<div class="empty">无结果 —— 查询没有返回任何行。</div>';
        return;
    }
    ?>
    <table>
      <thead>
        <tr>
          <?php foreach (array_keys($rows[0]) as $col): ?>
            <th><?= htmlspecialchars((string) $col) ?></th>
          <?php endforeach; ?>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($rows as $row): ?>
          <tr>
            <?php foreach ($row as $value): ?>
              <td class="mono"><?= htmlspecialchars((string) $value) ?></td>
            <?php endforeach; ?>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
    <?php
}

/**
 * 渲染难度切换链接。
 *
 * @param array<string,string> $levels 形如 ['low.php' => 'low', ...]
 */
function render_level_switcher(array $levels, string $current): void
{
    ?>
    <div class="links">
      <?php foreach ($levels as $file => $label): ?>
        <a href="<?= htmlspecialchars($file) ?>"
           class="<?= basename($file) === $current ? 'cur' : '' ?>">
          难度：<?= htmlspecialchars($label) ?>
        </a>
      <?php endforeach; ?>
    </div>
    <?php
}

/**
 * 显示目标目录里「现在有哪些文件」。
 *
 * 反序列化场景用它来解释一种很容易被误判为失败的情况：
 *
 *   副作用检查比对的是「新增」文件。如果攻击者两次都用同一个文件名，
 *   第二次只是**覆盖**了已有文件 —— 目录里没有多出任何东西，
 *   检查就会显示"没有新文件"，看起来像这次没有成功。
 *
 *   把目录现有内容列出来，使用者就能自己判断是哪种情况。
 *
 * @param list<string> $files 目录中的文件名
 */
function render_file_list_note(array $files): void
{
    if (!$files) {
        return;
    }
    ?>
    <p class="hint" style="margin:12px 0 0">
      目标目录现在有：
      <?php foreach ($files as $f): ?>
        <code><?= htmlspecialchars($f) ?></code>
      <?php endforeach; ?>
      <br>
      <span style="opacity:.75">
        如果这个列表里就有你打算写的文件名，那说明上一次已经写成功了 ——
        本次不动目录只是因为**覆盖同名文件不会产生"新"文件**。
      </span>
    </p>
    <?php
}
