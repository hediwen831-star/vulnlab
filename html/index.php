<?php
/**
 * VulnLab 首页 —— 漏洞矩阵。
 *
 * 用表格直观展示「本项目覆盖了哪些漏洞、每档难度做到什么程度、
 * 是否提供 Writeup 与可机读 PoC」。
 * 这个矩阵既是使用者的导航，也是项目完整度的自我声明。
 */

declare(strict_types=1);

require __DIR__ . '/config.php';
require __DIR__ . '/lib/layout.php';

$matrix = [
    [
        'name'    => 'SQL 注入',
        'href'    => 'sqli/low.php',
        'levels'  => ['low', 'medium', 'high'],
        'writeup' => true,
        'poc'     => true,
        'note'    => '数字型未过滤 / 黑名单过滤可双写绕过 / 参数化查询修复对照',
    ],
    [
        'name'    => 'XSS（反射型）',
        'href'    => 'xss/low.php',
        'levels'  => ['low', 'medium', 'high'],
        'writeup' => true,
        'poc'     => true,
        'note'    => '无转义输出 / 标签黑名单可用事件属性绕过 / 输出编码修复对照',
    ],
    [
        'name'    => '文件上传（getshell）',
        'href'    => 'upload/low.php',
        'levels'  => ['low', 'medium', 'high'],
        'writeup' => true,
        'poc'     => true,
        'note'    => '零校验+原名保存 / 只信客户端 MIME / 白名单+内容检查+重命名+禁执行',
    ],
    [
        'name'    => 'SSRF（打内网服务）',
        'href'    => 'ssrf/low.php',
        'levels'  => ['low', 'medium', 'high'],
        'writeup' => true,
        'poc'     => true,
        'note'    => '无限制 / 字符串黑名单可被 localhost 绕过 / 解析后校验 IP',
    ],
    [
        'name'    => '命令注入（RCE）',
        'href'    => 'cmdi/low.php',
        'levels'  => ['low', 'medium', 'high'],
        'writeup' => true,
        'poc'     => true,
        'note'    => '直接拼接 / 黑名单漏掉 & / 白名单 + escapeshellarg 双层修复',
    ],
];
?>
<?php layout_header('VulnLab — 自研 Web 漏洞靶场', '覆盖 OWASP Top 10 的漏洞场景，每个场景配源码、Writeup 与可被自动化扫描器消费的 PoC。'); ?>

<div class="grid two">
  <div class="card">
    <h3 style="margin-top:0">这个靶场和你见过的有什么不同</h3>
    <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
      很多靶场只提供「有漏洞的页面」。本站额外做了三件事：
    </p>
    <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
      <li><b>每档都贴出服务端实际执行的 SQL</b> —— 让你看到拼接后语句变成了什么</li>
      <li><b>每档都配修复对照</b> —— 不只教你打，还教你改</li>
      <li><b>每个漏洞都提供机读 PoC</b> —— 可作为扫描器效果评测基准</li>
    </ul>
  </div>
  <div class="card">
    <h3 style="margin-top:0">环境信息</h3>
    <div class="kv"><b>PHP</b><span class="mono"><?= htmlspecialchars(PHP_VERSION) ?></span></div>
    <div class="kv"><b>数据库</b><span class="mono"><?= htmlspecialchars(DB_DRIVER) ?></span></div>
    <div class="kv"><b>服务器</b><span class="mono"><?= htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? 'built-in') ?></span></div>
    <div class="kv">
      <b>测试账号</b>
      <span class="mono">
        <?php
        $names = array_map(function ($u) {
            return $u['username'];
        }, seed_users());
        echo htmlspecialchars(implode(' / ', $names));
        ?>
      </span>
    </div>
    <p class="hint" style="margin-top:12px">
      通关凭证藏在 <code>users.secret</code> 字段里，只有成功注入才能读到。
    </p>
  </div>
</div>

<h2>漏洞矩阵</h2>
<table>
  <thead>
    <tr>
      <th style="width:26%">漏洞类型</th>
      <th style="width:20%">难度档位</th>
      <th style="width:12%">Writeup</th>
      <th style="width:12%">PoC</th>
      <th>说明</th>
    </tr>
  </thead>
  <tbody>
    <?php foreach ($matrix as $item): ?>
      <tr>
        <td>
          <a href="<?= htmlspecialchars($item['href']) ?>" style="font-weight:500;text-decoration:none">
            <?= htmlspecialchars($item['name']) ?>
          </a>
        </td>
        <td>
          <?php foreach ($item['levels'] as $level): ?>
            <span class="tag <?= htmlspecialchars($level) ?>"><?= htmlspecialchars($level) ?></span>
          <?php endforeach; ?>
        </td>
        <td><?= $item['writeup'] ? '&#10003;' : '&mdash;' ?></td>
        <td><?= $item['poc'] ? '&#10003;' : '&mdash;' ?></td>
        <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($item['note']) ?></td>
      </tr>
    <?php endforeach; ?>
    <tr>
      <td>PHP 反序列化</td>
      <td><span class="tag">规划中</span></td>
      <td>&mdash;</td>
      <td>&mdash;</td>
      <td style="color:var(--dim);font-size:13px">POP 链构造与 __wakeup 绕过</td>
    </tr>
    <tr>
      <td>越权（水平 / 垂直）</td>
      <td><span class="tag">规划中</span></td>
      <td>&mdash;</td>
      <td>&mdash;</td>
      <td style="color:var(--dim);font-size:13px">IDOR 与角色校验缺失</td>
    </tr>
  </tbody>
</table>

<h2>怎么用</h2>
<div class="card">
  <h3 style="margin-top:0">1. 手工练习</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    从 <a href="sqli/low.php">SQL 注入</a> 开始。页面顶部可以直接切换难度档，
    右上角「查看源码」能看到当前页面的完整实现 —— 先看懂代码再动手，比盲试有效得多。
  </p>
  <h3>2. 自动化验证</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    <code>pocs/</code> 目录下的 YAML PoC 可被任意支持该类格式的扫描器加载；
    <code>poc_sqli.py</code> 是独立可运行的 Python 脚本，无需扫描器即可验证。
  </p>
  <h3>3. 作为扫描器评测基准</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    因为每个漏洞都有明确的 URL、明确的命中特征与明确的「是否存在漏洞」结论，
    本站可作为扫描器召回率 / 误报率的评测集使用。
  </p>
</div>

<?php layout_footer(); ?>
