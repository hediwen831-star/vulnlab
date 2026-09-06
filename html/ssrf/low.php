<?php
/**
 * SSRF（服务端请求伪造）· low 档
 *
 * 漏洞成因：服务端**代替用户**发起了一个用户指定的请求，且不做任何限制。
 *
 * SSRF 的本质是一个「信任边界」问题：
 *
 *   服务端通常处在网络拓扑的**内层**（能访问内网、能访问云元数据、能访问
 *   只监听回环地址的服务），而攻击者在**外层**。
 *   当服务端愿意替攻击者发请求时，**攻击者就获得了服务端的网络位置**。
 *
 * 这也是为什么 SSRF 在现代渗透里地位很高 ——
 * 它是「从外网打点」到「进入内网」的关键跳板，云环境下还能直接拿到
 * 云主机的临时凭据（169.254.169.254 元数据接口）。
 *
 * 本档的目标是访问一个「模拟的内网服务」：
 *   /internal/inner-service.php
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';

$url = isset($_GET['url']) ? (string) $_GET['url'] : '';
$submitted = ($url !== '');

$content = '';
$error = '';
$httpCode = 0;
$elapsed = 0.0;
$effectiveUrl = '';

if ($submitted) {
    // ------------------------------------------------------------------
    // 漏洞点：直接请求用户提供的 URL，没有任何限制
    //
    // 既没有校验协议（file:// 可以读本地文件），
    // 也没有校验目标地址（可以打内网、打回环、打云元数据接口）。
    // ------------------------------------------------------------------
    $started = microtime(true);

    $context = stream_context_create([
        'http' => [
            'method'        => 'GET',
            'timeout'       => 5,
            'ignore_errors' => true,     // 让 4xx/5xx 也能拿到响应体
            'follow_location' => 0,      // 本档不跟随跳转，保持行为可预期
        ],
        'ssl' => [
            'verify_peer'      => false,
            'verify_peer_name' => false,
        ],
    ]);

    $content = @file_get_contents($url, false, $context);
    $elapsed = microtime(true) - $started;

    if ($content === false) {
        $error = '请求失败。可能的原因：目标不可达、协议不支持、或被 PHP 配置禁止。';
        // 即使失败，$http_response_header 里可能有状态码
        if (isset($http_response_header[0])) {
            $error .= ' 服务器返回：' . $http_response_header[0];
        }
    } else {
        if (isset($http_response_header[0])) {
            if (preg_match('#HTTP/\S+\s+(\d+)#', $http_response_header[0], $m)) {
                $httpCode = (int) $m[1];
            }
        }
    }
}

/** 演示用的目标（内网服务地址由 INTERNAL_BASE 决定，见 config.php） */
$targets = [
    INTERNAL_BASE . '/internal/inner-service.php' => '内网服务（本档目标）',
    INTERNAL_BASE . '/index.php'                  => '内网服务的首页',
    'http://127.0.0.1:3306/'                      => '本机 MySQL 端口（探测内网服务）',
    'http://127.0.0.1:6379/'                      => '本机 Redis 端口',
    'file:///C:/Windows/win.ini'                  => '本地文件（file 协议）',
];
?>
<?php layout_header(
    'SSRF · 难度 low',
    '服务端替你发请求，且不限制去哪儿 —— 它把你带进了它所在的网络。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">没有任何限制：</p>
  <pre style="margin:10px 0 0">$content = @file_get_contents($url, false, $context);
<span class="c">// $url 来自用户，协议不限、目标不限</span></pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    读取 <code>/internal/inner-service.php</code> 的内容 ——
    那里有一个模拟的内部接口，它「假设外部访问不到」。
  </p>
</div>

<div class="card">
  <form class="inline" method="get" action="low.php">
    <input type="text" name="url"
           value="<?= htmlspecialchars($url) ?>"
           placeholder="http://127.0.0.1:8080/internal/inner-service.php"
           style="min-width:420px">
    <button type="submit">发起请求</button>
  </form>
  <p class="hint">
    服务端会用 <code>file_get_contents()</code> 请求你给的地址，然后把结果返回给你。
  </p>
</div>

<?php if ($submitted): ?>
  <?php
  render_code_board(
      '服务端这次实际发起了什么请求',
      "协议: " . (parse_url($url, PHP_URL_SCHEME) ?: '(无法解析)') . "\n"
      . "主机: " . (parse_url($url, PHP_URL_HOST) ?: '(无法解析)') . "\n"
      . "端口: " . (parse_url($url, PHP_URL_PORT) ?: '(默认)') . "\n"
      . "完整 URL: {$url}\n\n"
      . "耗时: " . number_format($elapsed, 3) . " 秒"
      . ($httpCode ? "   HTTP {$httpCode}" : '')
  );
  ?>

  <?php if ($error !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
    </div>
  <?php else: ?>
    <div class="card">
      <h3 style="margin-top:0">响应内容</h3>
      <pre style="max-height:420px;overflow:auto"><?= htmlspecialchars(substr((string) $content, 0, 6000)) ?></pre>
      <?php if (strlen((string) $content) > 6000): ?>
        <p class="hint">（内容过长，仅显示前 6000 字节）</p>
      <?php endif; ?>
    </div>
  <?php endif; ?>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">可以试试的目标</h3>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:62%">URL</th><th>说明</th></tr></thead>
      <tbody>
        <?php foreach ($targets as $t => $note): ?>
          <tr>
            <td class="mono" style="word-break:break-all">
              <a href="?url=<?= rawurlencode($t) ?>"><?= htmlspecialchars($t) ?></a>
            </td>
            <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <p class="hint">
    点击即可填入表单。注意 <code>file://</code> 那条 —— 它证明了 SSRF 不只能打内网，
    还能直接读服务器本地文件。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">为什么 SSRF 的威胁等级通常很高</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>
      <b>它是一把「内网钥匙」。</b>
      服务端能访问的网络位置，攻击者通过它都能访问 —— 包括本不该暴露的内网服务。
    </li>
    <li>
      <b>云环境下可直接拿凭据。</b>
      <code>http://169.254.169.254/</code> 是各大云厂商的元数据接口，
      能读到云主机的临时凭据（进而接管云账号）。这是近年来最严重的 SSRF 利用路径。
    </li>
    <li>
      <b>它常与内网服务「无认证」的假设叠加。</b>
      很多内网服务不做鉴权，理由是「反正外面访问不到」——
      SSRF 恰好打破了那个前提。
    </li>
    <li>
      <b>它还是绕过防火墙的手段。</b>
      目标可能只允许特定服务器访问，SSRF 让攻击者借这台服务器的手过去。
    </li>
  </ul>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>服务端发请求时，用的是<b>谁的网络位置</b>？</li>
    <li>除了 <code>http://</code>，<code>file_get_contents</code> 还支持哪些协议？</li>
    <li>「内网服务没做认证」这件事，在什么前提下才是安全的？</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/ssrf.md</code>。</p>
</div>

<?php layout_footer(); ?>
