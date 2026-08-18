<?php
/**
 * SQL 注入 · high 档 —— 修复对照
 *
 * 这一档是**安全的**，本站把它保留下来是有意的：
 *
 *   一个只会教「怎么打」的靶场，培养出的是「只会说这里有问题」的人。
 *   面试官真正想听的是「应该怎么修，以及为什么这么修有效」。
 *
 * 本档用参数化查询（预编译语句）重写了同样的功能。
 * 页面下方用同一组 payload 做了对照实验，直观展示「为什么打不动」。
 *
 * 关键点：预编译之所以能根治注入，是因为它把「SQL 结构」和「数据」
 * 分两次发送给数据库 ——
 *
 *   ① 先用占位符 :id 发送语句模板，数据库完成语法解析并确定执行计划
 *   ② 再发送参数值，数据库把它**当作纯数据**填入
 *
 * 参数值哪怕长成 `1 OR 1=1` 的样子，也永远只是「一个字符串」，
 * 不可能变成语法。这就是「数据与代码分离」——
 * 而不是「把数据里的危险字符删掉」。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$id = isset($_GET['id']) ? (string) $_GET['id'] : '1';
$submitted = isset($_GET['id']);

// ------------------------------------------------------------------
// 这里是修复方案。
// 注意：整条语句里没有任何变量拼接，注入的物理条件（拼接）根本不存在。
//
// 进一步加固（生产环境还应做）：
//   1. 类型校验 —— 如果 id 本该是数字，先 (int) 转换，非法输入直接拒绝
//   2. 最小权限 —— 该查询只需 SELECT，数据库账号就不该有写权限
//   3. 关闭报错回显 —— 不把数据库错误暴露给客户端
// ------------------------------------------------------------------
$sql = 'SELECT id, username, email, role FROM users WHERE id = :id';

$rows = [];
$error = '';
$rejected = false;

if ($submitted) {
    // 第一层：类型校验。id 本该是整数，不是整数就直接拒绝，连数据库都不用碰。
    if (!preg_match('/^\d+$/', $id)) {
        $rejected = true;
    } else {
        try {
            // 第二层：参数化查询。
            // 这里即使 $id 是恶意内容，也只会被当作一个「值的字符串」，
            // 不会参与语法解析。
            $stmt = db()->prepare($sql);
            $stmt->execute([':id' => (int) $id]);
            $rows = $stmt->fetchAll();
        } catch (PDOException $e) {
            // 第三层：不把数据库错误返回给客户端。
            // 报错信息会泄漏表名、列名甚至数据库版本，是信息收集的重要来源。
            $error = '查询失败，请稍后重试。';
        }
    }
}

// 对照实验：同一组 payload 在本档下会发生什么
$attackSamples = [
    '1 UNION SELECT 1,username,email,role FROM users' => 'low 档的经典 payload',
    "1' union select 1,username,email,password from users-- " => 'medium 档绕过后依然有效',
    "1' OR '1'='1" => '最简单的万能条件',
    '1; DROP TABLE users-- ' => '堆叠查询 / 破坏性操作',
];
?>
<?php layout_header(
    'SQL 注入 · 难度 high（已修复）',
    '参数化查询 + 类型校验 + 错误信息收敛 —— 这一档打不动，作为修复对照保留。'
); ?>

<?php render_level_switcher(['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'], basename(__FILE__)); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护</h3>
  <p style="margin:0 0 10px;font-size:14px;color:#065f46">
    同样的功能，用参数化查询重写。语句里<b>不存在任何变量拼接</b>：
  </p>
  <pre style="margin:0;background:#064e3b">$sql  = <span class="s">'SELECT id, username, email, role FROM users WHERE id = :id'</span>;
$stmt = db()-&gt;prepare($sql);      <span class="c">// ① 先发结构，数据库完成语法解析</span>
$stmt-&gt;execute([<span class="s">':id'</span> =&gt; (int) $id]);  <span class="c">// ② 再发数据，永远只是「值」</span></pre>
</div>

<div class="card">
  <form class="inline" method="get" action="high.php">
    <input type="text" name="id" value="<?= htmlspecialchars($id) ?>"
           placeholder="输入用户 id，例如 1">
    <button type="submit">查询</button>
  </form>
  <p class="hint">
    试试把 low / medium 档里成功的 payload 直接粘进来 —— 不会成功。
  </p>
</div>

<?php if ($submitted): ?>
  <?php if ($rejected): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)">输入被拒绝</b>
      <p style="margin:8px 0 0;font-size:14px;color:#b91c1c">
        参数 <code>id</code> 必须是纯数字。
        请求在「类型校验」这一步就被挡住了，根本没有到达数据库 ——
        这比「到了数据库再想办法过滤」要安全得多。
      </p>
    </div>
  <?php else: ?>
    <?php render_sql_board($sql . "    -- 参数 :id = " . var_export((int) $id, true)); ?>

    <div class="card">
      <h3 style="margin-top:0">查询结果</h3>
      <?php if ($error !== ''): ?>
        <div class="empty" style="color:var(--danger)"><?= htmlspecialchars($error) ?></div>
      <?php else: ?>
        <?php render_users_table($rows); ?>
      <?php endif; ?>
    </div>
  <?php endif; ?>
<?php endif; ?>

<h2>对照实验：同一组 payload，为什么在这里全失效</h2>
<p class="sub" style="margin-bottom:12px">
  下面这些 payload 在 low / medium 档都能拿到结果。在 high 档，
  它们会被「类型校验」直接拒绝（不是被过滤掉内容，而是压根没到数据库）。
</p>
<table>
  <thead>
    <tr>
      <th style="width:52%">Payload</th>
      <th style="width:22%">来源</th>
      <th>在本档的结果</th>
    </tr>
  </thead>
  <tbody>
    <?php foreach ($attackSamples as $payload => $origin): ?>
      <tr>
        <td class="mono" style="word-break:break-all"><?= htmlspecialchars($payload) ?></td>
        <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($origin) ?></td>
        <td><span class="tag high">被类型校验拒绝</span></td>
      </tr>
    <?php endforeach; ?>
  </tbody>
</table>

<div class="card" style="margin-top:20px">
  <h3 style="margin-top:0">修复要点总结（面试会问的部分）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>参数化查询是根治手段</b>，不是「更严格的过滤」。
      区别在于：过滤是在「危险字符出现在数据里」这个前提下做补救，
      而参数化让危险字符从一开始就不可能变成语法。
    </li>
    <li>
      <b>类型校验是第二道防线</b>。id 不是数字就该直接拒绝 ——
      越早拒绝非法输入，攻击面越小。
    </li>
    <li>
      <b>错误信息必须收敛</b>。回显数据库报错会泄漏表名、列名与版本，
      是攻击者构造 payload 的重要依据。生产环境应记录到日志而不是返回给客户端。
    </li>
    <li>
      <b>最小权限原则</b>。这个查询只需要读权限，那么数据库账号就只该有 SELECT。
      即使哪天又出现注入，攻击者也写不了、删不了。
    </li>
    <li>
      <b>「转义引号」不等于安全</b>。转义只在字符串上下文里有意义；
      数字型注入点根本不需要引号（见 low 档）。
    </li>
  </ul>
</div>

<?php layout_footer(); ?>
