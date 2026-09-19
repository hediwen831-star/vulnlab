<?php
/**
 * XXE · high 档 —— 修复对照
 *
 * 修复方式：**三层一起上，每一层各自能独立挡住 XXE。**
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码的修复版，请勿删改其中的防护逻辑。
 *
 * ══════════════════════════════════════════════════════════════════
 * 为什么这里不用黑名单
 * ══════════════════════════════════════════════════════════════════
 *
 * 前两档的失败模式：
 *
 *   low    ：把「替换实体」打开 + 不限制来源 → 任意读文件
 *   medium ：黑名单挡住 `<!ENTITY` —— 但实体声明可以放到外部 DTD 里，
 *            过滤器看不见，解析器却能加载
 *
 * medium 的问题不在于「黑名单写得不全」，而在于**它管错了地方**：
 * 过滤的是「文本里有没有某个字符串」，而漏洞的能力来自
 * 「解析器被允许做什么」。只要解析器还允许加载并展开外部实体，
 * 无论过滤多少种写法，总会有新的等价路径。
 *
 * 所以修复的方向是**关掉解析器的能力**，而不是枚举攻击者的写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 三层防护，各自独立生效
 * ══════════════════════════════════════════════════════════════════
 *
 *   ① 不传 LIBXML_NOENT
 *      实体默认**不做替换**。就算文档里声明了实体、就算解析器允许加载外部
 *      资源，`&xxe;` 也只会被当成一个未被替换的实体引用，不会变成文件内容。
 *
 *      ⚠️ 只靠这一层是不够的 —— 如果业务代码某处为了别的原因加回了 NOENT，
 *         这层就没了。所以还需要下面两层。
 *
 *   ② 禁掉外部实体加载器
 *      `libxml_set_external_entity_loader()` 换成「一律返回 null」的回调。
 *      这样**任何**外部资源（本地文件、远程 URL、外部 DTD）都加载不了。
 *
 *      这一层是真正的兜底：它管的是「解析器能不能读到外部的东西」，
 *      与文档怎么写、什么编码、走内部还是外部子集都无关。
 *
 *   ③ 拒绝带 DOCTYPE / ENTITY 的文档
 *      本接口的业务只需要纯数据 XML（`<order><id>1001</id></order>`），
 *      DTD 完全用不到。既然用不到，就直接不接受 ——
 *      这层是「按业务需要收窄输入」，也是最直观的一层。
 *
 * 本靶场刻意保留三层，是为了说明：
 * **修复不是「找一个万无一失的开关」，而是让能力本身不存在。**
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/../lib/paths.php';

const PROBE_FILE = 'xxe_probe.txt';

$xml = isset($_POST['xml']) ? (string) $_POST['xml'] : '';
$submitted = ($xml !== '');

$orderId = '';
$error = '';
$audit = [];
$warnings = [];
$entityRead = false;

if ($submitted) {
    // ------------------------------------------------------------------
    // 层 ②：把外部实体加载器换成一个永远返回 null 的回调
    //
    // 这是本档最关键的一行。它不检查输入，而是直接拿掉解析器
    // 「去外面取东西」的能力 —— 返回 null 意味着「这里没有你要的资源」，
    // 于是任何 SYSTEM 指向的实体都拿不到内容。
    //
    // 注：这个设置是进程级的，会影响后续所有解析。
    // 如果同一进程里还有别的 XML 解析逻辑需要外部资源，要把它隔离处理。
    // ------------------------------------------------------------------
    libxml_set_external_entity_loader(static function () {
        return null;
    });
    $audit[] = ['② 外部实体加载器', '已替换为「一律返回 null」', '✓ 外部资源不可达'];

    // ------------------------------------------------------------------
    // 层 ③：按业务需要收窄输入 —— 本接口不需要 DTD
    // ------------------------------------------------------------------
    $hasDoctype = stripos($xml, '<!DOCTYPE') !== false;
    $hasEntity  = stripos($xml, '<!ENTITY') !== false;
    if ($hasDoctype || $hasEntity) {
        $audit[] = [
            '③ 输入收窄',
            $hasDoctype ? '发现 <!DOCTYPE' : '发现 <!ENTITY',
            '✗ 本接口不需要 DTD，直接拒绝',
        ];
        $error = '请求被拒绝：本接口只接受纯数据 XML，不支持 DTD。';
    } else {
        $audit[] = ['③ 输入收窄', '（无 DOCTYPE / ENTITY）', '— 通过'];
    }

    if ($error === '') {
        libxml_use_internal_errors(true);

        // ------------------------------------------------------------------
        // 层 ①：不传 LIBXML_NOENT
        //
        // 对比 low / medium 档 —— 那边是 LIBXML_NOENT（替换实体），
        // 这里只传 LIBXML_NONET（禁止网络访问，属于额外的纵深防御）。
        //
        // 「不传某个标志」是一种很容易被改回去的防护：
        // 几个月后有人为了支持某个格式加上了 NOENT，这层就悄悄没了。
        // 正因为如此才需要 ② 兜底。
        // ------------------------------------------------------------------
        $flags = LIBXML_NONET;
        $audit[] = ['① 实体替换', 'LIBXML_NOENT 未启用', '✓ 实体不被替换'];

        $doc = @simplexml_load_string($xml, 'SimpleXMLElement', $flags);

        if ($doc === false) {
            $error = 'XML 解析失败。';
        } else {
            $orderId = trim((string) $doc->id);
            // 本档不该出现「非 1001」的内容；如果出现，说明三层都没挡住
            $entityRead = ($orderId !== '' && $orderId !== '1001');
        }

        foreach (libxml_get_errors() as $e) {
            $warnings[] = trim($e->message);
        }
        libxml_clear_errors();
    }
}

/** 演示用的正常订单 */
$normalXml = "<?xml version=\"1.0\"?>\n<order>\n  <id>1001</id>\n</order>";

/** 攻击载荷对照（页面上列出来，方便逐条验证都被挡住） */
$attacks = [
    "<!DOCTYPE order [<!ENTITY xxe SYSTEM \"xxe_probe.txt\">]>\n<order><id>&xxe;</id></order>"
        => '内联实体（low 档的手法）',
    "<!DOCTYPE order SYSTEM \"attacker.dtd\">\n<order><id>&xxe;</id></order>"
        => '外部 DTD（medium 档的绕过手法）',
];
?>
<?php layout_header(
    'XXE · 难度 high（已修复）',
    '不问「攻击者能写出什么花样」，只问「解析器还需要哪些能力」。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护（三层）</h3>
  <pre style="margin:10px 0 0;background:#064e3b"><span class="c">// ① 不传 LIBXML_NOENT —— 实体不替换</span>
$doc = simplexml_load_string($xml, <span class="s">'SimpleXMLElement'</span>, <span class="f">LIBXML_NONET</span>);

<span class="c">// ② 外部实体加载器换成「一律返回 null」—— 外部资源不可达</span>
libxml_set_external_entity_loader(static function () { return <span class="f">null</span>; });

<span class="c">// ③ 按业务需要收窄输入 —— 本接口用不到 DTD，直接拒绝</span>
if (stripos($xml, <span class="s">'&lt;!DOCTYPE'</span>) !== <span class="f">false</span>) { <span class="c">/* 拒绝 */</span> }</pre>
  <p style="margin:10px 0 0;font-size:14px;color:#065f46">
    <b>第二层是关键。</b>它不检查输入，而是直接拿掉解析器「去外面取东西」的能力 ——
    因此与文档怎么写、什么编码、走内部还是外部子集都无关。
  </p>
</div>

<div class="card">
  <form method="post" action="high.php">
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
  <p class="hint">把 low / medium 档成功的 payload 原样粘进来试试 —— 三层各自都会让它失败。</p>
</div>

<?php if ($submitted): ?>
  <div class="card tight" style="margin-bottom:14px">
    <div style="font-size:13px;color:var(--muted);margin-bottom:10px">校验过程（逐层审计）</div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th style="width:22%">层</th><th style="width:46%">观察到的值</th><th>结果</th></tr></thead>
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

  <div class="card">
    <h3 style="margin-top:0">解析结果</h3>
    <?php if ($error !== ''): ?>
      <p style="margin:0;color:var(--danger);font-weight:500"><?= htmlspecialchars($error) ?></p>
    <?php else: ?>
      <div class="kv">
        <b>订单号（&lt;id&gt; 的内容）</b>
        <span class="mono" style="word-break:break-all">订单号：<b><?= htmlspecialchars($orderId !== '' ? $orderId : '(空)') ?></b></span>
      </div>
      <?php if ($entityRead): ?>
        <p style="margin:12px 0 0;color:var(--danger);font-weight:500">
          ★ 严重：外部实体内容出现在了 id 里 —— 三层防护已被绕过
        </p>
      <?php elseif ($orderId === '1001'): ?>
        <p style="margin:12px 0 0;color:var(--ok);font-weight:500">
          ✓ 正常订单照常解析 —— 修复没有牺牲功能
        </p>
      <?php endif; ?>
    <?php endif; ?>

    <?php if ($warnings): ?>
      <?php render_code_board('libxml 警告', implode("\n", array_slice($warnings, 0, 5))); ?>
    <?php endif; ?>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">攻击载荷对照（都被挡住）</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:26%">载荷</th><th>被哪一层挡住</th></tr></thead>
      <tbody>
        <?php foreach ($attacks as $payload => $label): ?>
          <tr>
            <td style="font-size:13px"><?= htmlspecialchars($label) ?></td>
            <td style="font-size:13px;color:var(--muted)">
              ③ 直接拒绝（含 DOCTYPE）<br>
              <span style="opacity:.75">
                即使把 ③ 去掉：② 会让外部资源加载失败；
                即使把 ② 也去掉：① 会让实体不被替换。<br>
                <b>三层任意一层单独存在都能挡住。</b>
              </span>
            </td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>

<div class="card">
  <h3 style="margin-top:0">修复要点总结</h3>
  <ol style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>不传 <code>LIBXML_NOENT</code></b> —— 实体替换默认是关的，不要为了「方便」打开它
    </li>
    <li>
      <b>用 <code>libxml_set_external_entity_loader()</code> 禁掉外部实体加载</b> ——
      这是唯一与「文档怎么构造」无关的防线
    </li>
    <li>
      <b>按业务需要收窄输入</b> —— 不需要 DTD 的场景就直接拒绝带 DTD 的文档
    </li>
    <li>
      <b>别用 <code>LibXML</code> 之外的解析器「自动」了事</b> ——
      换 JSON 通常是最干净的方案：<code>json_decode</code> 既没有实体、也没有 DTD，
      从语言层面就不存在这个攻击面
    </li>
    <li>
      <b>如果必须支持外部 DTD</b>，那就得接受「它会去取外部资源」这件事，
      需要把 DTD 加载限制在受控的来源上（白名单域名 / 本地固定目录），
      而不是靠过滤文档内容
    </li>
  </ol>
  <p class="hint">
    最容易踩的一条：<b>「我过滤了 <code>&lt;!ENTITY</code>」不是修复。</b><br>
    medium 档就是为了说明这件事 —— 实体声明可以放在请求体之外，
    过滤器看不到，解析器却会去加载它。
  </p>
</div>

<?php layout_footer(); ?>
