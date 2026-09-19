<?php
/**
 * 极简 JWT 实现 —— JWT 场景三档共用。
 *
 * ══════════════════════════════════════════════════════════════════
 * 为什么这里自己实现，而不是引第三方库
 * ══════════════════════════════════════════════════════════════════
 *
 * JWT 的格式简单到「看一遍就能自己写」——
 * 三段 base64url 用点号连接，第三段是前两段的签名。就这些。
 *
 * 而这个「简单」恰恰是问题的来源：**很多项目就是自己手写的**，
 * 于是把格式抄对了，却在算法的判断上留了口子。
 * 本场景要演示的正是这类手写实现的典型缺陷，所以用原生代码实现，
 * 每一行的行为都摆在明面上，不需要读者去翻库的内部逻辑。
 *
 * ⚠️ 本文件包含三档共用的实现。其中 low / medium 档**故意写得有问题**，
 *    具体缺陷在各档页面里说明。请勿在任何真实项目中使用这套写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * JWT 的结构
 * ══════════════════════════════════════════════════════════════════
 *
 *      header . payload . signature
 *      ───┬──   ───┬───   ────┬────
 *         │        │          └─ 对前两段的签名（base64url）
 *         │        └─ 载荷：{"user":"alice","role":"user"}
 *         └─ 头部：{"alg":"HS256","typ":"JWT"}
 *
 * 关键点：**header 和 payload 都是攻击者可以读、也可以改的明文**。
 * 它们只是 base64url 编码，不是加密。
 *
 * 所以 JWT 的安全性**完全**建立在第三段签名上 ——
 * 而签名能不能被伪造，取决于两件事：
 *
 *   ① 算法判断是否严格（攻击者能不能让服务端用「不校验」的方式处理）
 *   ② 密钥强度是否足够（攻击者能不能暴力猜到）
 *
 * 本场景的三档就是围绕这两件事展开的。
 */

declare(strict_types=1);

/** 通关凭证 —— 只有 role=admin 才能看到 */
const JWT_FLAG = 'VULNLAB{jwt_signature_bypass}';

/** 签发 token 时用的「当前用户」（模拟已登录的普通用户） */
const JWT_DEMO_USER = ['user' => 'alice', 'role' => 'user'];


/**
 * base64url 编码 —— 就是 base64 换掉两个字符、去掉填充。
 *
 * 为什么不用普通 base64：`+` `/` `=` 在 URL 里有特殊含义，
 * 放在 token 里会被转义或截断。所以 JWT 规范换成了 `-` `_` 和无填充。
 */
function b64url_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}


/**
 * base64url 解码 —— 需要把填充补回来。
 *
 * ⚠️ 补填充这一步不能省：`base64_decode` 对长度不是 4 的倍数的输入
 * 会直接失败。而 JWT 规范要求去掉填充，所以几乎每个 token
 * 都会走到这里补一次。
 */
function b64url_decode(string $data): string
{
    $remainder = strlen($data) % 4;
    if ($remainder !== 0) {
        $data .= str_repeat('=', 4 - $remainder);
    }
    return (string) base64_decode(strtr($data, '-_', '+/'), true);
}


/** 计算 HS256 签名：对 `header.payload` 做 HMAC-SHA256，再 base64url 编码 */
function jwt_hs256_sign(string $signingInput, string $secret): string
{
    return b64url_encode(hash_hmac('sha256', $signingInput, $secret, true));
}


/**
 * 生成一个 token。
 *
 * @param array<string,mixed> $payload 载荷
 * @param string              $alg     算法名
 * @param string              $secret  密钥（alg 为 none 时忽略）
 */
function jwt_encode(array $payload, string $alg, string $secret = ''): string
{
    $header = ['alg' => $alg, 'typ' => 'JWT'];

    $h = b64url_encode((string) json_encode($header, JSON_UNESCAPED_SLASHES));
    $p = b64url_encode((string) json_encode($payload, JSON_UNESCAPED_SLASHES));
    $signingInput = $h . '.' . $p;

    // alg 为 none 时，规范规定签名为空串
    if ($alg === 'none') {
        return $signingInput . '.';
    }

    return $signingInput . '.' . jwt_hs256_sign($signingInput, $secret);
}


/**
 * 把 token 拆成四部分，并做最基本的格式检查。
 *
 * @return array{0: ?array<string,mixed>, 1: ?array<string,mixed>, 2: string, 3: string, 4: string}
 *         依次为 [header, payload, signature, signingInput, error]
 */
function jwt_split(string $token): array
{
    $parts = explode('.', $token);

    if (count($parts) !== 3) {
        return [null, null, '', '', 'JWT 必须由三部分组成（用 . 分隔）'];
    }

    [$rawHeader, $rawPayload, $signature] = $parts;

    $header = json_decode(b64url_decode($rawHeader), true);
    $payload = json_decode(b64url_decode($rawPayload), true);

    if (!is_array($header) || !is_array($payload)) {
        return [null, null, '', '', 'JWT 的 header 或 payload 不是合法的 JSON 对象'];
    }

    if (!isset($header['alg']) || !is_string($header['alg'])) {
        return [null, null, '', '', 'JWT 的 header 里缺少 alg 字段'];
    }

    return [$header, $payload, $signature, $rawHeader . '.' . $rawPayload, ''];
}


/**
 * 渲染「拆解结果」表格，三档共用。
 *
 * 把 header / payload / 签名校验结果都摊开显示 ——
 * 使用者能直接看到「服务端眼里的 token 是什么样」，
 * 而不用靠猜来判断自己的构造对不对。
 *
 * @param array<string,mixed> $header
 * @param array<string,mixed> $payload
 * @param array<string,string> $extra 额外的行（键 => 值）
 */
function render_jwt_breakdown(array $header, array $payload, string $signature, array $extra = []): void
{
    $rows = [
        ['header', (string) json_encode($header, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)],
        ['payload', (string) json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)],
        ['signature（原始）', $signature === '' ? '(空)' : $signature],
    ];
    foreach ($extra as $k => $v) {
        $rows[] = [$k, $v];
    }
    ?>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th style="width:26%">段</th><th>值</th></tr></thead>
        <tbody>
          <?php foreach ($rows as [$label, $value]): ?>
            <tr>
              <td><?= htmlspecialchars($label) ?></td>
              <td class="mono" style="word-break:break-all;font-size:12px">
                <?= htmlspecialchars($value !== '' ? $value : '(空)') ?>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php
}
