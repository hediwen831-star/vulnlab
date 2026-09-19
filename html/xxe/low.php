<?php
/**
 * XXE（XML 外部实体注入）· low 档
 *
 * 漏洞成因：解析 XML 时传入了 `LIBXML_NOENT`，而没有任何来源限制。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * XXE 和前面几个场景的区别：漏洞点在「解析器的开关」上
 * ══════════════════════════════════════════════════════════════════
 *
 * SQL 注入、命令注入是【拼接】造成的，文件包含是【路径】造成的，
 * 反序列化是【类与属性】造成的。XXE 不一样：
 *
 *   下面这行代码没有任何拼接、没有任何用户输入参与字符串构造 ——
 *
 *       simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
 *                                                  ^^^^^^^^^^^^
 *   问题出在第三个参数这个【标志位】上。
 *
 * `LIBXML_NOENT` 的字面意思是 "substitute entities"（替换实体）。
 * 而 XML 的「实体」可以指向**外部资源** —— 包括本地文件、远程 URL。
 * 于是「替换实体」就等于「把外部资源的内容读进来，放进文档里」。
 *
 * 攻击者要做的只有一件事：**自己写一个实体声明**。
 *
 *   <!DOCTYPE order [
 *     <!ENTITY xxe SYSTEM "file:///etc/passwd">   ← 声明一个指向文件的实体
 *   ]>
 *   <order><id>&xxe;</id></order>                  ← 在正文里引用它
 *
 * 解析器遇到 `&xxe;` 就会去读那个文件、把内容填进来 ——
 * 而应用拿到 `$order->id` 时，它已经是文件内容了。
 *
 * 整个过程不需要应用「拼接」任何东西，也不需要应用「执行」任何东西。
 * 这是 XML 解析器的**内置能力**被打开了 ——
 * 也是为什么 XXE 常常出现在「代码看起来完全正常」的地方。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/../lib/paths.php';

/** 演示读的目标文件（放在本目录下，内容是固定标记串） */
const PROBE_FILE = 'xxe_probe.txt';

$xml = isset($_POST['xml']) ? (string) $_POST['xml'] : '';
$submitted = ($xml !== '');

$orderId = '';
$error = '';
$warnings = [];
$entityRead = false;

if ($submitted) {
    // 把 libxml 的警告收集起来自己处理（否则会直接打到响应里，污染页面）
    libxml_use_internal_errors(true);

    // ------------------------------------------------------------------
    // 漏洞点：LIBXML_NOENT = 替换实体
    //
    // 没有第二个约束了 —— 没有 LIBXML_NONET、没有禁掉外部实体加载器、
    // 没有检查 DTD、没有白名单。
    //
    // 一句话概括：把「文档里能声明什么样的实体」这个决定权，
    // 完全交给了提交文档的人。
    // ------------------------------------------------------------------
    $doc = @simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);

    if ($doc === false) {
        $error = 'XML 解析失败。';
    } else {
        $orderId = trim((string) $doc->id);
        $entityRead = ($orderId !== '' && $orderId !== '1001');
    }

    foreach (libxml_get_errors() as $e) {
        $warnings[] = trim($e->message);
    }
    libxml_clear_errors();
}

/** 演示用的正常订单（供对照） */
$normalXml = "<?xml version=\"1.0\"?>\n<order>\n  <id>1001</id>\n</order>";
?>
<?php layout_header(
    'XXE · 难度 low',
    'XML 的实体可以指向外部资源 —— 打开「替换实体」就等于允许读文件。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    XXE 能读服务器上的任意可读文件，还可能被用于探测内网、触发 SSRF、
    甚至在某些环境（配合 <code>expect://</code>）直接执行命令。<br>
    本靶场只演示<b>读取</b>一个无害的演示文件，请勿构造读取敏感文件的载荷。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$doc = <span class="v">simplexml_load_string</span>($xml, <span class="s">'SimpleXMLElement'</span>, <span class="f">LIBXML_NOENT</span>);
<span class="c">//                                             ^^^^^^^^^^^^ 就是这一位</span>
<span class="c">// 没有 NONET，没有禁外部实体加载器，没有 DTD 检查</span></pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    这个接口接收一段 XML 订单查询，返回其中的 <code>&lt;id&gt;</code> 字段。
    想办法让 <b>id 里出现文件内容</b>。
  </p>
  <?php render_target_dir_hint(__DIR__, 'xxe 目录'); ?>
  <p class="hint" style="margin:8px 0 0">
    演示文件是 <code><?= htmlspecialchars(PROBE_FILE) ?></code>（就在本目录下），
    内容是固定标记串 <code>VULNLAB_XXE_PROBE_MARKER</code>。
    <br>
    <span style="opacity:.75">
      用它而不是系统文件（<code>/etc/passwd</code>、<code>win.ini</code>）的原因：
      系统文件在不同机器上不一定存在、内容也不一样，
      会让「读到没有」这件事本身变得不可判断。
      换成固定内容的演示文件，判据就只取决于漏洞是否成立。
    </span>
  </p>
</div>

<div class="card">
  <form method="post" action="low.php">
    <div class="row">
      <textarea name="xml" rows="7" style="flex:1;font-family:var(--mono);font-size:13px"
                placeholder='&lt;?xml version="1.0"?&gt;&#10;&lt;order&gt;&lt;id&gt;1001&lt;/id&gt;&lt;/order&gt;'
      ><?= htmlspecialchars($xml) ?></textarea>
    </div>
    <div class="row">
      <button type="submit">查询订单</button>
      <button type="submit" formnovalidate
              onclick="document.querySelector('textarea').value = <?= json_encode($normalXml, JSON_UNESCAPED_UNICODE) ?>">
        填入正常订单
      </button>
    </div>
  </form>
</div>

<?php if ($submitted): ?>
  <div class="card" style="<?= $entityRead ? 'border-color:#fecaca;background:var(--danger-soft)' : '' ?>">
    <h3 style="margin-top:0">解析结果</h3>

    <?php if ($error !== ''): ?>
      <p style="margin:0;color:var(--danger);font-weight:500">
        <?= htmlspecialchars($error) ?>
      </p>
    <?php else: ?>
      <div class="kv">
        <b>订单号（&lt;id&gt; 的内容）</b>
        <span class="mono" style="word-break:break-all">订单号：<b><?= htmlspecialchars($orderId !== '' ? $orderId : '(空)') ?></b></span>
      </div>

      <?php if ($entityRead): ?>
        <p style="margin:12px 0 0;color:var(--danger);font-weight:500">
          ★ 该字段出现了非预期的内容 —— 说明外部实体被解析器读取并替换进来了
        </p>
      <?php endif; ?>

      <?php render_code_board(
          '解析出的文档结构',
          trim(print_r(json_decode(json_encode($doc), true), true))
      ); ?>
    <?php endif; ?>

    <?php if ($warnings): ?>
      <?php render_code_board('libxml 警告', implode("\n", array_slice($warnings, 0, 5))); ?>
    <?php endif; ?>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>XML 文档开头的 <code>&lt;!DOCTYPE ...&gt;</code> 是干什么用的？</li>
    <li><code>&lt;!ENTITY 名字 SYSTEM "地址"&gt;</code> 声明了什么东西？这里的「地址」可以是什么格式？</li>
    <li>文档里用 <code>&amp;名字;</code> 引用的地方，解析器会拿什么内容来替换？</li>
    <li>对照一下：<b>如果解析时没有 <code>LIBXML_NOENT</code> 这个标志，上面那套还成立吗？</b>（high 档会验证这一点）</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/xxe.md</code>。</p>
</div>

<?php layout_footer(); ?>
