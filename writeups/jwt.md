# JWT 签名绕过 Writeup

场景目录：`html/jwt/` · 机读 PoC：`pocs/vulnlab-jwt-signature-bypass.yaml`
CI 断言：8 条（见 `tests/verify_lab.py`）

---

## 一、原理：JWT 的安全性 100% 在第三段上

JWT 是三个 base64url 段用点号连起来的字符串：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 . eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9 . xxx
────────────────┬─────────────────   ─────────────────┬────────────────────   ──┬──
                │                                    │                        │
          header：{"alg":"HS256","typ":"JWT"}   payload：{"user":"alice",...}   签名
```

**关键事实：前两段是 base64url 编码，不是加密。**

```bash
$ echo 'eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9' | base64 -d
{"user":"alice","role":"user"}
```

任何人都能读、也能改。所以：

**JWT 的全部安全性，都建立在「第三段没法被伪造」这一件事上。**

而签名能不能被伪造，取决于两件事，本场景的三档正好各打一个：

| 档 | 问题 | 性质 |
|---|---|---|
| low | 服务端会接受「声明自己没有签名」的 token | **逻辑问题** |
| medium | 算法判断写对了，但签名密钥能被猜到 | **配置问题** |

这是本场景最想传达的一点：**这两个问题的性质完全不同，
所以「把校验逻辑写对」并不能解决第二个。**

---

## 二、low 档：`alg: none`

### 2.1 漏洞代码

```php
if ($header['alg'] === 'none') {
    // 规范里 alg:none 表示「这个 token 没有签名」
    // —— 那就没有可校验的东西了
    $verifyNote = '已跳过'; $granted = true;    // ← 问题在这一行
} elseif ($header['alg'] === 'HS256') {
    // 正常校验签名
} else {
    // 不认识的算法 —— 这里也放行了
    $granted = true;
}
```

### 2.2 为什么这个分支看起来是合理的

因为 `alg: none` **是 JWT 规范里合法的一种算法**，含义是「这个 token 没有签名」。
它的设计初衷是给「已经在可信通道里传输」的场景用的
（比如服务内部调用、TLS 双向认证之后）。

于是代码逻辑读起来毫无问题：

`alg` 是 `none` → 规范说这种情况没有签名 → 那就没什么可校验的 → 通过。

**每一步都成立，结论却是错的。**

问题出在最后一步的隐含假设：

「没有签名可校验」的正确处理是**拒绝这个 token**，而不是「那就算它通过」。

一句话概括：

**「无法验证它」不等于「它是可信的」。**

这和前面几个场景是不同层面的问题：前面是「防护没拦住」，
这里是「把不设防当成了合规」。

### 2.3 利用

只需要三步：

```python
header  = {"alg": "none", "typ": "JWT"}
payload = {"user": "alice", "role": "admin"}

h = base64url(json(header))
p = base64url(json(payload))
token = f"{h}.{p}."        # 注意：第三段是空的，token 以 . 结尾
```

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4ifQ.
```

**第三段是空的** —— 这不是格式错误，而是规范对 `alg:none` 的规定。
服务端解析时先看到 `alg=none`，走进「跳过校验」的分支，
于是 `role=admin` 被照单全收。

不用算任何签名、不用知道任何密钥、不用爆破 —— 改一个字段就完事。

### 2.4 low 档还有第二个口子

注意上面代码里的 `else` 分支：**不认识的算法也放行**。

这看着像是「兼容性考虑」，实质是同一个错误：

**把「不知道怎么处理它」当成了「那就放它过去」。**

实测 `{"alg":"ES256"}` 甚至 `{"alg":"foo"}` 都能通过。

正确的写法永远是反过来：

```php
if (!in_array($header['alg'], ['HS256'], true)) {
    // 拒绝
}
```

**判据是「支持什么」，而不是「什么是危险的」。**

---

## 三、medium 档：算法对了，密钥弱了

### 3.1 防护措施

```php
// 算法白名单
if ($header['alg'] !== 'HS256') { /* 拒绝 */ }

// 正常校验签名（比较用 hash_equals，防时序侧信道）
if (hash_equals($expected, $signature)) { /* 通过 */ }

// 密钥
const MEDIUM_SECRET = 'secret';   // ← 问题在这里
```

到这一步，「绕过校验」这条路彻底走不通了：
`alg:none` 会被拒、签名不匹配会被拒、比较还是定长的。

### 3.2 攻击换了目标

既然校验绕不过去，那就让手里的 token 通过校验。

HS256 的签名是：

```
signature = HMAC-SHA256(header + "." + payload, 密钥)
```

一个纯数学运算。**密钥一旦已知，任何人都能算出合法签名。**

所以攻击从「绕过校验」变成了「猜密钥」：

```python
# 1. 拿一个自己的 token，把 header.payload 和签名段拆出来
h, p, sig = my_token.split(".")

# 2. 用字典里的词逐个试
for guess in wordlist:
    if base64url(hmac(guess, f"{h}.{p}")) == sig:
        print("密钥是:", guess)      # → secret
        break

# 3. 改成 admin，用猜到的密钥重新签名
forged = jwt_encode({"user": "alice", "role": "admin"}, "HS256", guess)
```

靶场自带一份 31 条的缩减字典（`html/jwt/wordlist.txt`），实测**第一条命中**。

### 3.3 这一档想说明什么

medium 的代码比 low **更正确** —— 但安全性并没有更高。

因为它把一个致命问题留在了配置里：**密钥是人的记忆产物。**

- `secret` / `jwtsecret` / `changeme` / `123456` ……
- 这些词的共同点是：**出现在教程、示例代码、脚手架默认配置里**

也就是说，攻击者不需要「猜」—— **照着常见示例的密钥列表试就行了**。
字典攻击之所以有效，正是因为大量真实系统用了同一批词。

**把校验写对，和让校验有意义，是两件不同的事。**
一个用 `secret` 当密钥的 HS256 实现，代码可以完全正确，
但它挡不住任何一个会写脚本的人。

---

## 四、high 档：四层防护

### 4.1 修复代码

```php
// ① 算法白名单 —— 只列举受支持的算法
if (!in_array($header['alg'], ['HS256'], true)) { /* 拒绝 */ }

// ② 高熵密钥 —— 从环境变量读
$secret = getenv('JWT_SECRET') ?: HIGH_SECRET_DEFAULT;   // 32 字节随机

// ③ 定长比较
if (!hash_equals($expected, $signature)) { /* 拒绝 */ }

// ④ 必需声明
if (!is_int($payload['exp'] ?? null) || $payload['exp'] < time()) { /* 拒绝 */ }
```

### 4.2 为什么 ① 和 ② 缺一不可

| 只修 ① | 只修 ② |
|---|---|
| 算法判断正确，但密钥还是 `secret` → **退回 medium 的水平** | 密钥很强，但 `alg:none` 能绕过 → **退回 low 的水平** |

它们针对的是两个独立的问题：

- ① 修的是「服务端会不会被说服不去校验」
- ② 修的是「就算校验，签名能不能被算出来」

**安全修复要对着「问题的成因」修，而不是对着「上次那个 payload」修。**

### 4.3 关于 ③ `hash_equals`

`===` 在第一个不同的字节处就返回，比较时间会随「猜对了多少字节」而变化。
理论上可以据此逐字节爆破签名。

这一层在实际攻击里较难利用（网络抖动通常远大于比较时间差），
但成本极低、没有理由不写 —— 这类「便宜且正确」的防护应该默认做。

### 4.4 关于 ④ `exp`

签名有效只说明「这个 token 由服务端签发」，**不代表它现在还能用**。

少了这一层，一个泄露的旧 token 会永远有效 ——
哪怕用户已经改密、哪怕账号已经禁用。
所以校验必需声明（`exp` / `iat` / `aud` / `iss`）不是可选项。

### 4.5 一个关于密钥存放的坦白

靶场把 high 档的密钥写在源码里（`HIGH_SECRET_DEFAULT`），是为了让场景开箱即用。
**但真实项目不该这样。**

```php
// 正确做法
$secret = getenv('JWT_SECRET');
if ($secret === false || strlen($secret) < 32) {
    throw new RuntimeException('JWT_SECRET 未配置或过短，拒绝启动');
}
```

注意两个细节：

1. **走环境变量 / 密钥管理服务**，不要写进代码和配置仓库
2. **缺失时必须拒绝启动**，而不是退回到一个默认弱密钥 ——
   后面这种做法比没有密钥更危险，因为它会安静地降级

顺带说明一点：high 档的页面对「通过校验的 admin token」的提示措辞是
「这个 token 确实是由持有密钥的一方签发的」，
而不是「伪造成功」—— 因为**服务端无法区分这两者**。
这正是「JWT 的防护上限就是密钥的保密程度」这句话的含义。

---

## 五、其他值得知道的手法

### 5.1 算法混淆（RS256 → HS256）

本靶场只实现了 HS256，所以没法完整演示这个手法，但值得知道它的形状：

有些服务用 RS256（非对称）：**私钥签名、公钥验签**。
公钥是可以公开的，甚至常常暴露在 `/.well-known/jwks.json` 里。

攻击者把 header 里的 `alg` 改成 `HS256`，
然后**用那个公开的公钥当 HMAC 密钥**去算签名。

一个实现有缺陷的库会：

```php
$alg = $header['alg'];                        // 攻击者说是 HS256
$key = $this->getKey($alg);                   // 于是它去取「HS256 的密钥」
                                              // —— 而那个位置放的是公钥
if (hash_hmac($alg, $input, $key) === $sig)   // 攻击者用公钥算的签名
```

**根本原因和 low 档一样：算法由 token 自己声明。**
正确的做法是「服务端决定用哪种算法，而不是听 token 的」。

### 5.2 其他常见问题

| 手法 | 说明 |
|---|---|
| `kid` 注入 | `kid` 是「用哪个密钥」的标识。可注入路径穿越（读任意文件当密钥）、SQL 注入、命令注入 |
| `jku` / `x5u` | 指向 JWKS 的 URL。指向攻击者的服务器即可用自己的密钥签名 |
| 空签名 | `alg:none` 之外，有些实现把「签名段为空」也当成合法 |
| 延长有效期 | payload 可以随便改 —— 前提是签名能被伪造 |

**共同点：所有这些字段都是 token 自己声明的，而服务端把它们当了真。**
这和 XXE 场景里「`SYSTEM` 指向哪里由文档作者决定」是同一类结构问题。

### 5.3 JWT 不适合做什么

很多项目把 JWT 当成了「有状态的会话」，于是遇到这些问题：

| 需求 | JWT 的天然短板 |
|---|---|
| 立即登出 | token 在过期前一直有效 —— 除非维护一份黑名单，那就又变成有状态了 |
| 改权限立即生效 | 权限写在 payload 里，改不动已签发的 token |
| 撤销单个会话 | 同上 |
| 缩小体积 | 塞进去的字段越多，token 越容易超过 header 长度限制 |

**如果这些需求对你很重要，服务端会话（session）往往比 JWT 更合适。**
JWT 的优势场景是「跨服务传递、无状态、短有效期」——
而不是「替代 session 做用户登录态」。

---

## 六、防御清单

| 优先级 | 做法 | 说明 |
|---|---|---|
| **①** | 算法**白名单** | 写「只接受 HS256」，而不是「除了 none 都接受」 |
| **①** | 密钥必须随机且足够长 | ≥32 字节随机值。**不要用想出来的词** |
| **②** | 密钥走环境变量 / KMS | 不进代码库；**缺失时拒绝启动**，不要退默认值 |
| **②** | 校验必需声明 | `exp` / `iat` / `aud` / `iss` |
| **③** | `hash_equals()` 比较 | 防时序侧信道，成本极低 |
| **③** | 短有效期 + 刷新机制 | 缩小泄露窗口 |
| **④** | 用成熟库 | 本场景是手写实现，为的是把缺陷摆在明面上 |

按有效性排序：**① > ② > ③ > ④**。

最后一条不是「兜底」，而是**默认选择** ——
成熟库已经替你处理了算法白名单、时序比较、声明校验这些细节。
手写 JWT 的唯一理由应该是「明确知道标准库为什么不满足需求」。

---

## 七、和本靶场其他场景的联系

### 7.1 「输入自己声明了该怎么处理它」

靶场里这是第三次出现这个结构：

| 场景 | 输入自己声明的 | 本该由谁决定 |
|---|---|---|
| 反序列化 | 实例化哪个类 | 业务代码 |
| XXE | 文档要加载哪些外部资源 | 解析器配置 |
| **JWT** | **用哪种算法校验** | **服务端** |

共同点一句话：

**任何「让输入自己决定如何处理自己」的设计，都是一个漏洞的形状。**

`alg` 这个字段的设计初衷是「告诉对方签名用的是哪个算法」——
它是一个**描述**，却被当成了**指令**。

### 7.2 与 SSRF 的联系

`jku` / `x5u` 是「URL 字段」，服务端会去请求它 ——
这就是 SSRF 的形状。SSRF 场景那条结论可以直接搬过来：

**校验必须发生在「解析之后」。**

对 JWT 来说就是：**密钥来源必须是配置，不能是 token 里给的地址。**

### 7.3 与命令注入的联系

medium 档「猜密钥」这一步，和命令注入里的字典爆破是同一件事：
**只要密钥出自人可以记住的范围，它就在字典里。**

靶场自带的 `wordlist.txt` 只有 31 条，真实攻击用的是几十万条。
但导致成功的从来不是字典的大小，而是**密钥是否出自人的记忆**。

---

## 八、延伸阅读

- [RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [Critical vulnerabilities in JSON Web Token libraries (Auth0)](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) —— `alg:none` 的经典披露
- [OWASP WSTG - Testing JSON Web Tokens](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)
- [jwt-secrets 字典](https://github.com/wallabag/jwt-secrets) —— 真实攻击用的弱密钥列表
