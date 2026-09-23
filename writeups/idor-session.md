# 越权 · 会话凭据可伪造

> 对应场景：`idor-session/low.php`、`medium.php`、`high.php`
> 机读 PoC：`pocs/vulnlab-idor-session-credential.yaml`

## 与 idor 场景的区别

`idor` 场景问的是：**服务端有没有校验资源归属**。

这个场景问的是另一个问题：**服务端凭什么相信「你是谁」**。

两件事经常被混为一谈，但它们互相独立：

| | 归属校验缺失 | 归属校验正确 |
|---|---|---|
| **凭据可伪造** | 越权（双重问题） | 越权（冒充他人身份） |
| **凭据不可伪造** | 越权（能读所有人的） | 无越权 |

四个格子有三个是漏洞。这一格一格地看，能解释为什么「加了权限判断」不等于「修好了」。

三档的设计：

| 档 | 凭据形态 | 归属校验 | 漏洞成因 |
|---|---|---|---|
| low | `Cookie: sid=<明文 uid>` | **无** | 详情查询漏了归属条件 |
| medium | `Cookie: sid=<base64(uid)>` | 有（SQL 正确） | 编码被当成签名 |
| high | `Cookie: sid=<随机令牌>` | 有 | — |

## low 档：同一条规则只落地了一处

打开页面，「我的订单」只列出自己的两条，看起来权限控制已经做了。

但那是**列表查询**里的条件：

```
列表：SELECT * FROM orders WHERE user_id = ?
详情：SELECT * FROM orders WHERE id = ?
```

同一个页面、同一张表、同一条业务规则，**只写了一处**。

这不是「不知道要做权限校验」——列表那里就写了。这是「同一条规则需要在两个地方分别实施，只落实了一个」。真实项目里凡是校验逻辑需要重复书写的地方，都是这个形状。

请求：

```
GET /idor-session/low.php?order_id=1003
Cookie: sid=2
```

`1003` 属于 bob（uid=3），而请求方是 alice（uid=2）。服务端返回了订单详情，备注里是通关凭证。

注意这一档用的凭据**完全合法** —— 越权不依赖任何伪造。这印证了上表的第一格：归属校验缺失本身就足以构成漏洞，与凭据强度无关。

## medium 档：编码不是签名

这一档有两处改动，都朝着「更安全」的方向：

```php
// ① Cookie 里不再是明文，看起来像加密过
$uid = (int) base64_decode($_COOKIE['sid'], true);

// ② 归属校验加上了 —— 这条 SQL 是对的
SELECT * FROM orders WHERE id = ? AND user_id = ?
```

评审时这两点很容易让人放心：值不可读、SQL 也对了。

但把它解开：

```
base64_decode("Mw==")  →  "3"
```

它是 uid 换了个写法而已。

三个容易混淆的概念：

| 机制 | 需要密钥 | 客户端能否伪造 |
|---|---|---|
| 编码（base64 / hex / URL 编码） | 不需要 | **能** |
| 签名（HMAC / RSA） | 需要 | 不能（没有密钥） |
| 加密（AES 等） | 需要 | 不能（构造不出合法密文） |

base64 解决的是「让数据不含有特殊字符、便于传输」，它从来没有打算解决「防止篡改」。

请求：

```
GET /idor-session/medium.php?order_id=1003
Cookie: sid=Mw==
```

改一个字符就把身份换成了 bob。**归属校验正常工作了 —— 它只是被喂了一个假身份。**

判别方法只有一句：

> 凭据里的信息，客户端能不能自己造出来？

能造出来的（明文、base64、自增 ID、时间戳拼的串）就不是凭据。造不出来的（服务端随机的、带密钥签名的）才是。

## high 档：把「算得出」换成「拿不到」

```php
// 服务端生成随机令牌，记住它对应哪个用户
$token = bin2hex(random_bytes(6));
$tokenStore[$token] = $uid;

// 下次请求：查表还原身份（不是解码，是查表）
$uid = $tokenStore[$_COOKIE['sid']] ?? null;

// 归属校验照旧
SELECT * FROM orders WHERE id = ? AND user_id = ?
```

关键差别在最后一行注释：**令牌里不编码任何信息**。

low 和 medium 的 `sid` 都是**从 uid 算出来的**，只要知道算法就能造出任意一个（而算法必然公开，因为客户端要能构造请求）。high 档的 `sid` **不是算出来的，是发出来的** —— 客户端手里只有自己那一个。

PHP 自己的 `session_start()` 就是这套机制：`PHPSESSID` 是随机串，服务端把「随机串 → 会话数据」存在文件或 Redis 里。它安全的唯一原因是随机值猜不出来，**而不是因为客户端看不见** —— 会话 ID 本来就在 Cookie 里，客户端看得见，这没关系。

实测：

| 请求 | 结果 |
|---|---|
| `sid=a1b2c3d4e5f6`（alice 的令牌）读 1003 | 拒绝（归属校验挡住） |
| `sid=f7e8d9c0b1a2`（bob 的令牌）读 1003 | 成功（本人访问） |
| `sid=deadbeef0000`（自己造的）读 1003 | 拒绝（表中无此条目） |
| 不带 Cookie | 拒绝（未登录） |

注意第二行：**凭据合法不等于能读别人的数据**。这一档有两个独立的东西在起作用 —— 凭据强度、授权判断。

## 开发时踩到的一个坑

写 medium / high 档时，第一版实现里「未登录」和「不做归属过滤」用了同一个 `null`：

```php
$order = session_find_order($orderId, $effectiveUid);   // $effectiveUid 可能是 null
```

而 `session_find_order($id, null)` 的语义是「不按归属过滤」（low 档需要它）。

结果：**凭据无效的人反而能读到所有订单** —— 伪造一个令牌，越权成功。防护被整个绕过。

这个缺陷是跑实测才暴露的：13 条身份逻辑用例里，只有「伪造令牌」那一条失败。静态看代码看不出来，因为两处 `null` 在各自的位置上都「说得通」。

修法是让「未登录」直接短路，不要把 `null` 传进查询：

```php
if ($effectiveUid === null) {
    $error = '凭据无效或已失效 —— 未登录，拒绝查询。';
} else {
    $order = session_find_order($orderId, $effectiveUid);
    ...
}
```

现在有一条 CI 断言专门守这个（`会话凭据 · medium 档无效凭据被拒`），覆盖非法 base64、不存在的 uid、空值三种输入。

## 真实世界里的形态

会话凭据可伪造在真实项目里常见于：

- Cookie 里存 `user_id=123`、`role=admin`、`is_admin=1`（明文，最直白）
- 把上面的值做 base64 / hex / 自定义编码后存入 Cookie，注释写着「已加密」
- JWT 读取 `sub` 声明但**没有校验签名**
- 网关注入的 `X-User-Id` 请求头 —— 绕过网关直连应用服务器时该头可以被自己填

共同点是：**这个值来自请求方，而不是服务端自己算出来的。**

## 防御清单

**应做**

- 身份只从服务端持有的映射中还原：随机会话 ID + 服务端存储（文件 / Redis / 数据库）
- 会话令牌用密码学安全的随机源生成，长度足够（`random_bytes` 而不是 `rand`、`mt_rand`、时间戳）
- 令牌设置 `HttpOnly`、`Secure`、`SameSite` 属性，并支持服务端主动失效（登出、改密码后轮换）
- 登录后轮换会话 ID（防止会话固定攻击）
- 授权判断同时使用服务端身份和资源归属条件，两者都在服务端完成

**不应做**

- 不要把 uid、角色、权限标志直接放进 Cookie（明文或编码后都不行）
- 不要用 base64 / hex / rot13 / 自定义编码当作防护手段，它不提供任何防篡改能力
- 不要只用 `(int)` 转换当作对身份值的校验 —— 它只做类型转换，不验证来源
- 不要相信任何来自请求的身份声明：`uid` 参数、`X-User-Id` 头、未验签的 JWT 字段
- 不要用「令牌猜不到」代替授权判断 —— ID 会从分享链接、日志、Referer、浏览器历史泄露

## 相关

- [OWASP Top 10 A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [WSTG — Testing for Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- 相邻场景：`writeups/idor.md`（归属校验缺失）、`writeups/jwt.md`（签名绕过）
