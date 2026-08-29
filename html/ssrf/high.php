<?php
/**
 * SSRF · high 档 —— 修复对照
 *
 * 修复的核心思路只有一句话：
 *
 *   **先把主机名解析成真实 IP，再对这个 IP 做判断 —— 而不是对 URL 做字符串匹配。**
 *
 * 三层防护：
 *
 *   ① 协议白名单      —— 只允许 http/https，堵住 file:// / gopher:// / dict:// 等
 *   ② 解析后校验 IP   —— 判断解析出的 IP 是否在私有/保留网段
 *   ③ 用校验过的 IP 发请求 —— 防 DNS 重绑定（TOCTOU）
 *
 * ══════════════════════════════════════════════════════════════════
 * 第 ③ 层为什么必须存在（这是 SSRF 修复里最容易漏的一点）
 * ══════════════════════════════════════════════════════════════════
 *
 * 如果这样写：
 *
 *     $ip = gethostbyname($host);      // 第一次解析：返回公网 IP，校验通过
 *     if (is_private($ip)) die();
 *     file_get_contents($url);         // 第二次解析：攻击者让 DNS 返回 127.0.0.1
 *                                        // ↑ 请求实际打到了内网
 *
 * 攻击者只需要控制一个域名，把它的 A 记录 TTL 设为 0，
 * 第一次查询返回公网 IP、第二次返回 127.0.0.1 —— 校验就形同虚设。
 * 这叫 **DNS 重绑定攻击**（TOCTOU：校验时和使用时看到的东西不是同一个）。
 *
 * 正确做法是：**校验的是哪个 IP，请求就打到哪个 IP**，
 * 不要再让它多解析一次。
 *
 * ⚠️ 补充说明：即使在应用层做全了这三层，SSRF 依然难以说"彻底修复"。
 *    真正的纵深防御还需要网络层配合 —— 见页面下方的说明。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$url = isset($_GET['url']) ? (string) $_GET['url'] : '';
$submitted = ($url !== '');

$content = '';
$error = '';
$audit = [];
$elapsed = 0.0;

/** 允许的协议 */
const ALLOWED_SCHEMES = ['http', 'https'];

/**
 * 判断 IP 是否属于私有 / 保留网段。
 *
 * 这里必须覆盖全 —— 漏掉任何一段都可能被利用：
 *   10.0.0.0/8      私有
 *   172.16.0.0/12   私有
 *   192.168.0.0/16  私有
 *   127.0.0.0/8     回环
 *   169.254.0.0/16  链路本地（**云元数据接口就在这一段**）
 *   0.0.0.0/8       本地网络
 *   100.64.0.0/10   运营商级 NAT
 *   192.0.0.0/24    IETF 保留
 *   198.18.0.0/15   基准测试
 *   224.0.0.0/4     组播
 *   240.0.0.0/4     保留
 *
 * 另外还要处理 IPv6 的 ::1 和 IPv4 映射地址（::ffff:127.0.0.1）。
 */
function is_private_ip(string $ip): bool
{
    // IPv6 回环与映射地址
    if (strpos($ip, ':') !== false) {
        $normalized = strtolower($ip);
        if ($normalized === '::1' || $normalized === '::') {
            return true;
        }
        // IPv4 映射的 IPv6（::ffff:127.0.0.1）
        if (strpos($normalized, '::ffff:') === 0) {
            return is_private_ip(substr($normalized, 7));
        }
        // 其他 IPv6 一律拒绝（本靶场只处理 IPv4 场景）
        return true;
    }

    $long = ip2long($ip);
    if ($long === false) {
        return true;      // 解析不出来 → 保守拒绝
    }

    $privateRanges = [
        ['0.0.0.0',     8],
        ['10.0.0.0',    8],
        ['100.64.0.0', 10],
        ['127.0.0.0',   8],
        ['169.254.0.0', 16],
        ['172.16.0.0', 12],
        ['192.0.0.0',  24],
        ['192.168.0.0', 16],
        ['198.18.0.0', 15],
        ['224.0.0.0',   4],
        ['240.0.0.0',   4],
    ];

    foreach ($privateRanges as [$network, $bits]) {
        $mask = -1 << (32 - $bits);
        if (($long & $mask) === (ip2long($network) & $mask)) {
            return true;
        }
    }
    return false;
}

if ($submitted) {
    // ── 第 ① 层：协议白名单 ──────────────────────────────────────
    //
    // ⚠️ 顺序很重要：**协议校验必须在主机解析之前**。
    //
    // 踩过的坑：最初把「主机是否为空」放在前面判断，结果
    // `file:///C:/Windows/win.ini` 这种 URL 的 host 部分本来就是空的，
    // 于是走的是「URL 格式不合法」分支，而不是「协议不允许」分支。
    // 虽然两种情况都拒绝了，但错误原因定位错了 ——
    // 而且如果哪天有人放宽了「主机为空」的检查，协议限制就会一起失效。
    //
    // 一般原则：**先做粗粒度的边界检查（协议、长度），再做细粒度的解析。**
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    $host = (string) parse_url($url, PHP_URL_HOST);

    if (!in_array($scheme, ALLOWED_SCHEMES, true)) {
        $error = "协议 {$scheme}:// 不在白名单内（只允许 http / https）。";
        $audit[] = ['① 协议校验', "{$scheme}://", '✗ 拒绝'];
    } elseif ($host === '') {
        $error = 'URL 格式不合法，无法解析出主机名。';
        $audit[] = ['① 协议校验', "{$scheme}://", '✓ 通过'];
        $audit[] = ['② 主机解析', '—', '✗ 无法解析出主机名'];
    } else {
        $audit[] = ['① 协议校验', "{$scheme}://", '✓ 通过'];

        // ── 第 ② 层：解析后校验 IP ──────────────────────────────
        //
        // 关键：gethostbyname 会把所有等价写法（127.1 / 0x7f000001 /
        // 2130706433 / 攻击者域名）统一解析成真实 IP，
        // 所以针对解析结果做判断，才能覆盖所有变形。
        $resolvedIp = gethostbyname($host);

        if ($resolvedIp === $host && filter_var($host, FILTER_VALIDATE_IP) === false) {
            $error = "无法解析主机名 {$host}。";
            $audit[] = ['② 主机解析', $host, '✗ 解析失败'];
        } else {
            $audit[] = ['② 主机解析', "{$host} → {$resolvedIp}", '✓ 已解析'];

            if (is_private_ip($resolvedIp)) {
                $error = "拒绝访问：{$host} 解析到内网地址 {$resolvedIp}。";
                $audit[] = ['③ 地址校验', $resolvedIp, '✗ 属于内网/保留网段'];
            } else {
                $audit[] = ['③ 地址校验', $resolvedIp, '✓ 公网地址'];

                // ── 第 ③ 层：用校验过的 IP 发请求（防 DNS 重绑定）──
                //
                // 把 URL 里的主机名替换成已验证的 IP，同时保留原始 Host 头。
                // 这样"校验的"和"请求的"就是同一个地址，不给攻击者二次解析的机会。
                $port = parse_url($url, PHP_URL_PORT);
                $path = (string) parse_url($url, PHP_URL_PATH);
                $query = parse_url($url, PHP_URL_QUERY);
                $portPart = $port ? ":{$port}" : '';
                $pathPart = $path === '' ? '/' : $path;
                $queryPart = $query ? "?{$query}" : '';

                $pinnedUrl = "{$scheme}://{$resolvedIp}{$portPart}{$pathPart}{$queryPart}";

                $context = stream_context_create([
                    'http' => [
                        'method'        => 'GET',
                        'timeout'       => 5,
                        'ignore_errors' => true,
                        'header'        => "Host: {$host}\r\n",
                    ],
                    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
                ]);

                $started = microtime(true);
                $content = @file_get_contents($pinnedUrl, false, $context);
                $elapsed = microtime(true) - $started;

                $audit[] = ['④ 固定地址请求', $pinnedUrl, '✓ 已发出'];

                if ($content === false) {
                    $error = '请求失败（目标不可达）。';
                }
            }
        }
    }
}

$attacks = [
    'http://127.0.0.1:8090/internal/inner-service.php'      => '直连回环',
    'http://localhost:8090/internal/inner-service.php'      => '★ localhost 写法（medium 档就是被这个绕过的）',
    'http://127.1:8090/internal/inner-service.php'          => '省略段写法（Linux 有效）',
    'http://2130706433:8090/internal/inner-service.php'     => '十进制写法（Linux 有效）',
    'file:///C:/Windows/win.ini'                            => 'file 协议读本地文件',
    'http://169.254.169.254/latest/meta-data/'              => '云元数据接口（最危险的利用路径）',
];
?>
<?php layout_header(
    'SSRF · 难度 high（已修复）',
    '协议白名单 + 解析后校验 IP + 用校验过的 IP 发请求 —— 这一档打不动。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#a7f3d0;background:var(--ok-soft)">
  <h3 style="margin-top:0;color:var(--ok)">这一档的防护：三层</h3>
  <div class="tbl-wrap" style="margin-top:10px">
    <table>
      <thead><tr><th style="width:26%">层</th><th style="width:30%">手段</th><th>挡住什么</th></tr></thead>
      <tbody>
        <tr>
          <td><b>① 协议白名单</b></td>
          <td><code>in_array($scheme, ['http','https'])</code></td>
          <td><code>file://</code> / <code>gopher://</code> / <code>dict://</code> 等协议</td>
        </tr>
        <tr>
          <td><b>② 解析后校验 IP</b></td>
          <td><code>gethostbyname</code> + 网段判断</td>
          <td><b>所有</b> IP 变形写法（127.1 / 十六进制 / 域名）</td>
        </tr>
        <tr>
          <td><b>③ 固定已校验的 IP</b></td>
          <td>替换 URL 主机名 + 保留 Host 头</td>
          <td>DNS 重绑定（TOCTOU）</td>
        </tr>
      </tbody>
    </table>
  </div>

  <h3>关键代码</h3>
  <pre style="margin:0">$scheme = strtolower(parse_url($url, PHP_URL_SCHEME));
if (!in_array($scheme, [<span class="s">'http'</span>, <span class="s">'https'</span>], true)) { <span class="c">/* 拒绝 */</span> }   <span class="c">// ①</span>

$resolvedIp = gethostbyname($host);                                <span class="c">// ② 解析</span>
if (is_private_ip($resolvedIp))                        { <span class="c">/* 拒绝 */</span> }   <span class="c">// ② 校验</span>

file_get_contents($pinnedUrlWithIp, ...);                          <span class="c">// ③ 用校验过的 IP 请求</span></pre>
</div>

<div class="card">
  <form class="inline" method="get" action="high.php">
    <input type="text" name="url"
           value="<?= htmlspecialchars($url) ?>"
           placeholder="把 low / medium 档成功的地址粘进来"
           style="min-width:420px">
    <button type="submit">发起请求</button>
  </form>
  <p class="hint">不会成功 —— 三种写法都会被 ② 层统一解析后拦下。</p>
</div>

<?php if ($submitted): ?>
  <div class="card tight" style="margin-bottom:14px">
    <div style="font-size:13px;color:var(--muted);margin-bottom:10px">校验过程（逐层审计）</div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th style="width:26%">层</th><th style="width:42%">观察到的值</th><th>结果</th></tr></thead>
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
        注意上面第 <b>② 主机解析</b> 那一行 —— 无论你用什么写法，
        最终都会被解析成同一个真实 IP，然后被同一套网段规则拦下。
        <b>这就是"解析后校验"相对"字符串匹配"的本质优势。</b>
      </p>
    </div>
  <?php endif; ?>

  <?php if ($error === '' && $content !== false && $content !== ''): ?>
    <div class="card">
      <h3 style="margin-top:0">响应内容</h3>
      <pre style="max-height:400px;overflow:auto"><?= htmlspecialchars(substr((string) $content, 0, 4000)) ?></pre>
    </div>
  <?php endif; ?>
<?php endif; ?>

<h2>对照实验：同一批地址，三档的结果</h2>
<p class="sub" style="margin-bottom:12px">
  这些在 low 档全部得手、在 medium 档大部分得手，在 high 档全部被拦。
</p>
<div class="tbl-wrap">
  <table>
    <thead><tr>
      <th style="width:44%">URL</th>
      <th style="width:28%">绕过的是什么</th>
      <th>high 档结果</th>
    </tr></thead>
    <tbody>
      <?php foreach ($attacks as $attack => $note): ?>
        <tr>
          <td class="mono" style="word-break:break-all">
            <a href="?url=<?= rawurlencode($attack) ?>"><?= htmlspecialchars($attack) ?></a>
          </td>
          <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          <td><span class="tag high">解析后校验拒绝</span></td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="card" style="margin-top:20px">
  <h3 style="margin-top:0">⚠️ 为什么 SSRF 很难「彻底修复」</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    即使应用层做全了上面三层，仍然存在一些难以在代码层解决的问题：
  </p>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>跳转（302）绕过</b>：目标 URL 返回 <code>Location: http://127.0.0.1/</code>，
      如果客户端跟随跳转，就绕过了所有校验。
      → 修复：不跟随跳转（<code>follow_location => 0</code>），或对每一跳都重新校验。
    </li>
    <li>
      <b>DNS 重绑定</b>：已用第 ③ 层处理，但要注意实现细节必须真的"用校验过的 IP"。
    </li>
    <li>
      <b>IPv6 的复杂性</b>：<code>::ffff:127.0.0.1</code>、
      <code>[0:0:0:0:0:ffff:7f00:1]</code> 等映射写法很容易漏判。
    </li>
    <li>
      <b>协议本身的利用</b>：某些协议（<code>gopher://</code>、<code>dict://</code>）
      可以构造任意 TCP 载荷去打内网服务。白名单协议是必须的。
    </li>
  </ul>
  <p style="margin:10px 0 0;font-size:14px;color:var(--muted)">
    <b>所以真正的 SSRF 防御必须包含网络层：</b>
  </p>
  <ul style="margin:8px 0 0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>让发起请求的服务运行在<b>隔离网段</b>，只放通它真正需要的出口</li>
    <li>云环境<b>禁用或加固元数据接口</b>（IMDSv2 要求 token，能挡掉大部分 SSRF）</li>
    <li>出站流量<b>白名单</b>：只允许访问特定的外部域名</li>
    <li>内网服务<b>不要依赖"外部访问不到"这个假设</b> —— 该做鉴权就做鉴权</li>
  </ul>
</div>

<div class="card">
  <h3 style="margin-top:0">修复要点总结（面试会问的部分）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>不要对 URL 做字符串匹配，要解析出真实 IP 再判断。</b>
      这是本档最重要的一条 —— 因为 IP 的表示法有无穷多种。
    </li>
    <li><b>协议白名单</b>，只允许 http/https。不能只靠黑名单。</li>
    <li>
      <b>网段判断要覆盖全</b>：私有段 + 回环 + 链路本地（<b>云元数据在 169.254.0.0/16</b>）
      + 保留段 + IPv6。
    </li>
    <li><b>用校验过的 IP 发请求</b>，防 DNS 重绑定（TOCTOU）。</li>
    <li><b>不跟随跳转</b>，或对每一跳重新校验。</li>
    <li>
      <b>网络层纵深防御</b>：隔离网段、出站白名单、元数据接口加固。
      应用层修得再好也可能被绕过，网络层是最后一道。
    </li>
    <li>
      <b>内网服务该做鉴权还是要做。</b>
      把安全性建立在「外部访问不到」上是危险的假设 —— SSRF 就是专门打破它的。
    </li>
  </ul>
</div>

<?php layout_footer(); ?>
