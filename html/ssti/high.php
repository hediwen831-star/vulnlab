<?php
/**
 * SSTI · high 档 —— 修复对照
 *
 * 修复方式：**不做表达式求值，只做变量替换。**
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码的修复版，请勿删改其中的防护逻辑。
 *
 * ══════════════════════════════════════════════════════════════════
 * 前两档的失败模式
 * ══════════════════════════════════════════════════════════════════
 *
 *   low    ：表达式直接 eval —— 用户可以调用任意函数
 *   medium ：不许出现括号 —— 但反引号运算符不需要括号就能执行命令
 *
 * 两档的共同点是：**它们都在「执行用户的表达式」。**
 * 区别只是执行之前做了多少检查 —— 而检查永远做不全。
 *
 * ══════════════════════════════════════════════════════════════════
 * 换个方向：不执行，就不会有执行漏洞
 * ══════════════════════════════════════════════════════════════════
 *
 * 回到业务需求：「通知模板里要能插入一些动态值」。
 *
 * 这个需求真正需要的其实只有一件事：**把预定义的值填进占位符**。
 * 它不需要用户能写表达式 —— 那只是为了省事而扩大的能力。
 *
 * 所以本档的做法是：
 *
 *     {{ name }}   →  去一个**预定义的变量表**里查 name，取到就替换
 *
 * 关键点有三个：
 *
 *   ① **没有 eval** —— 服务器上根本不存在「执行这个字符串」这一步
 *   ② **白名单查表** —— 表里没有的键直接拒绝，不存在「绕过」的概念
 *   ③ **语法收窄** —— 表达式必须是一个合法的标识符
 *      （`^[a-z_][a-z0-9_]*$`），`7*7`、`system('id')` 连格式都不合法
 *
 * 第 ② 点值得展开说：
 *
 *   黑名单问「这个输入危险吗」→ 需要枚举所有危险写法（不可能）
 *   白名单问「这个输入在我允许的列表里吗」→ 只需要枚举自己需要的东西
 *
 * **列表的完整性，第一次变得可以保证。**
 *
 * ══════════════════════════════════════════════════════════════════
 * 那如果业务真的需要表达式呢？
 * ══════════════════════════════════════════════════════════════════
 *
 * 本档的做法有个明显的代价：**模板里不能写 `{{ 199 * 2 }}` 了**。
 * 如果业务确实需要动态计算，正确的选择是：
 *
 *   · 用成熟模板引擎的**沙箱模式**（比如 Twig 的 SandboxExtension）
 *     —— 它把「允许调用哪些方法/属性」做成了一份显式清单
 *   · 或者把计算逻辑放在**服务端代码**里，模板只负责取值
 *
 * 无论哪种，都比「自己用 eval + 黑名单造一个模板引擎」可靠得多。
 *
 * 一句话：
 * **模板引擎是个难点，不是一个下午能写完的十几行正则。**
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/template.php';

const SSTI_PROBE_FILE = 'ssti_probe.txt';
const SSTI_CMD_MARKER = 'VULNLAB_SSTI_CMD_MARKER';

/**
 * 允许在模板里引用的变量 —— 这是本档防护的核心。
 *
 * 注意这里只放「展示用的数据」，没有任何「能力」：
 * 全是字符串和数字，就算模板把某个值渲染出来，也执行不了任何东西。
 */
const SSTI_ALLOWED_VARS = [
    'product'   => '示例商品',
    'price'     => '199',
    'quantity'  => '2',
    'total'     => '398',
    'username'  => 'alice',
];

$template = isset($_POST['template']) ? (string) $_POST['template'] : '';
$submitted = ($template !== '');

$rendered = '';
$expressions = [];
$audit = [];
$fileRead = false;
$cmdExecuted = false;

if ($submitted) {
    $expressions = ssti_find_expressions($template);

    $rendered = ssti_render($template, static function (string $expr) use (&$audit): string {
        // ------------------------------------------------------------------
        // 层 ①：语法收窄 —— 必须是一个合法的标识符
        //
        // `7*7` / `system('id')` / `` `whoami` `` 全都连格式都不合法，
        // 在这里就被挡住了。这一步不需要理解 PHP 的语法，
        // 只需要定义「我允许什么样的文本」。
        // ------------------------------------------------------------------
        if (preg_match('/^[a-z_][a-z0-9_]*$/', $expr) !== 1) {
            $audit[] = [$expr, '不是合法的变量名', '✗ 拒绝'];
            return '[不被允许的表达式]';
        }

        // ------------------------------------------------------------------
        // 层 ②：白名单查表 —— 表里没有就拒绝
        //
        // 注意这里没有「检查危险函数」这一步 —— 不需要。
        // 变量表里既然只有字符串和数字，就**不可能**取到可执行的东西。
        //
        // 这就是白名单的好处：防护的完整性由「表里有什么」决定，
        // 而那是一份我自己写的、可以完整检查的清单。
        // ------------------------------------------------------------------
        if (!array_key_exists($expr, SSTI_ALLOWED_VARS)) {
            $audit[] = [$expr, '变量表中不存在', '✗ 拒绝'];
            return '[未定义的变量]';
        }

        $audit[] = [$expr, SSTI_ALLOWED_VARS[$expr], '✓ 替换'];
        return (string) SSTI_ALLOWED_VARS[$expr];
    });

    $fileRead = strpos($rendered, 'VULNLAB_SSTI_FILE_MARKER') !== false;
    $cmdExecuted = strpos($rendered, SSTI_CMD_MARKER) !== false;
}

/** 本档的正常模板示例 —— 注意它是「取变量」，不是「算表达式」 */
$normalTemplate = "您好 {{ username }}，您购买的是 {{ product }}，共 {{ total }} 元。";
?>
<?php layout_header(
    'SSTI · 难度 high（已修复）',
    '不执行用户的表达式，就不会有执行漏洞 —— 修复的方向是「去掉能力」，不是「加强过滤」。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护</h3>
  <pre style="margin:10px 0 0;background:#064e3b"><span class="c">// ① 语法收窄 —— 必须是一个合法的变量名</span>
<span class="k">if</span> (<span class="v">preg_match</span>(<span class="s">'/^[a-z_][a-z0-9_]*$/'</span>, $expr) !== 1) { <span class="c">/* 拒绝 */</span> }

<span class="c">// ② 白名单查表 —— 表里没有就拒绝</span>
<span class="k">if</span> (!<span class="v">array_key_exists</span>($expr, SSTI_ALLOWED_VARS)) { <span class="c">/* 拒绝 */</span> }

<span class="c">// ③ 没有 eval —— 整个文件里不存在「执行这个字符串」这一步</span>
<span class="k">return</span> (string) SSTI_ALLOWED_VARS[$expr];</pre>
  <p style="margin:10px 0 0;font-size:14px;color:#065f46">
    <b>关键是第 ③ 点：没有 eval。</b><br>
    前两档都是「先执行，再想办法过滤」；这一档干脆没有「执行」这个动作 ——
    所以也就不存在「绕过过滤」这件事。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">可引用的变量（白名单，就是这几个）</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:30%">变量名</th><th>值</th></tr></thead>
      <tbody>
        <?php foreach (SSTI_ALLOWED_VARS as $k => $v): ?>
          <tr>
            <td class="mono"><?= htmlspecialchars($k) ?></td>
            <td class="mono"><?= htmlspecialchars($v) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <p class="hint">
    注意表里全是字符串和数字 —— <b>没有任何「能力」</b>。
    就算模板把某个值渲染出来，也执行不了任何东西。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">通知模板</h3>
  <form method="post" action="high.php">
    <div class="row">
      <textarea name="template" rows="5" style="flex:1;font-family:var(--mono);font-size:13px"
                placeholder="您好 {{ username }}，共 {{ total }} 元。"
      ><?= htmlspecialchars($template) ?></textarea>
    </div>
    <div class="row">
      <button type="submit">渲染</button>
      <button type="submit" formnovalidate
              onclick="document.querySelector('textarea').value = <?= json_encode($normalTemplate, JSON_UNESCAPED_UNICODE) ?>">
        填入正常模板
      </button>
    </div>
  </form>
  <p class="hint" style="margin:10px 0 0">
    把 low / medium 档成功的 payload 原样粘进来试试 —— 连第一层都过不去。
  </p>
</div>

<?php if ($submitted): ?>
  <?php if ($audit): ?>
    <div class="card tight" style="margin-bottom:14px">
      <div style="font-size:13px;color:var(--muted);margin-bottom:10px">校验过程（逐个表达式）</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th style="width:44%">表达式</th><th style="width:32%">观察到的值</th><th>结果</th></tr></thead>
          <tbody>
            <?php foreach ($audit as [$expr, $value, $result]): ?>
              <tr>
                <td class="mono" style="word-break:break-all"><?= htmlspecialchars($expr) ?></td>
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
  <?php endif; ?>

  <div class="card">
    <h3 style="margin-top:0">渲染结果</h3>
    <pre style="margin:0;white-space:pre-wrap"><?= htmlspecialchars($rendered) ?></pre>

    <?php if ($fileRead || $cmdExecuted): ?>
      <p style="margin:12px 0 0;color:var(--danger);font-weight:500">
        ★ 严重：表达式被真的执行了 —— 防护已被绕过
      </p>
    <?php elseif ($expressions): ?>
      <p style="margin:12px 0 0;color:var(--ok);font-weight:500">
        ✓ 上面的表达式全部被拒绝或按白名单替换 —— 没有任何东西被执行
      </p>
    <?php endif; ?>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">攻击载荷对照（都被挡住）</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:36%">载荷</th><th>被哪一层挡住</th></tr></thead>
      <tbody>
        <tr>
          <td class="mono" style="font-size:12.5px">{{ 7*7 }}</td>
          <td style="font-size:13px;color:var(--muted)">层 ①（不是合法变量名）</td>
        </tr>
        <tr>
          <td class="mono" style="font-size:12.5px">{{ file_get_contents('ssti_probe.txt') }}</td>
          <td style="font-size:13px;color:var(--muted)">层 ①（不是合法变量名）</td>
        </tr>
        <tr>
          <td class="mono" style="font-size:12.5px">{{ `echo VULNLAB_SSTI_CMD_MARKER` }}</td>
          <td style="font-size:13px;color:var(--muted)">
            层 ①（不是合法变量名）<br>
            <span style="opacity:.75">
              注意这一条 —— medium 档就是被它绕过的。
              在 high 档它连格式检查都过不去，因为这里根本不承认「表达式」这个概念。
            </span>
          </td>
        </tr>
        <tr>
          <td class="mono" style="font-size:12.5px">{{ admin }}</td>
          <td style="font-size:13px;color:var(--muted)">层 ②（合法变量名，但不在白名单表里）</td>
        </tr>
        <tr>
          <td class="mono" style="font-size:12.5px">{{ product }}</td>
          <td style="font-size:13px;color:var(--ok)">✓ 正常替换（白名单内的变量）</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<div class="card">
  <h3 style="margin-top:0">修复要点总结</h3>
  <ol style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>最好不要自己写模板引擎</b> —— 这是本场景的第一条建议。
      成熟引擎（Twig / Smarty / Blade）默认就有沙箱与转义，
      它们踩过的坑比一个下午能想出来的多得多
    </li>
    <li>
      <b>如果必须自己实现，就不要 eval</b> ——
      「不执行用户输入」是最彻底的修复，因为它取消了整个攻击面
    </li>
    <li>
      <b>用变量白名单代替表达式</b> ——
      模板里只允许引用预定义的值，表里没有就拒绝。
      防护的完整性由「表里有什么」决定，而那是你能完整检查的
    </li>
    <li>
      <b>如果业务真的需要表达式</b> —— 用成熟引擎的沙箱模式
      （例如 Twig 的 SandboxExtension），它把「允许调用什么」做成显式清单
    </li>
    <li>
      <b>别用黑名单</b> —— 反引号绕过就是这一条的反例。
      你要枚举的不是「攻击者的写法」，而是「语言有多少种等价表达」
    </li>
    <li>
      <b>别把用户输入和模板文本混在一起存</b> ——
      有些项目允许用户「编辑模板」，那等于把模板注入的入口完全敞开。
      模板文本应该只来自开发者，用户只能提供**数据**
    </li>
  </ol>
  <p class="hint">
    最容易踩的一条：<b>「我过滤了括号 / 过滤了 system / 过滤了 php 标签」。</b><br>
    medium 档就是为了说明这件事 —— 反引号运算符不需要括号，
    而且 PHP 表达同一个能力的方式远不止一种。
    <b>过滤是在缩小攻击面，不是取消攻击面。</b>
  </p>
</div>

<?php layout_footer(); ?>
