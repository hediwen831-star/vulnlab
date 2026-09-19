# CSRF（跨站请求伪造）Writeup

> 场景目录：`html/csrf/` · 机读 PoC：`pocs/vulnlab-csrf-state-change.yaml`
> 攻击者页面示例：`html/csrf/attacker.html`
> CI 断言：9 条（见 `tests/verify_lab.py`）

---

## 一、原理：攻击目标不是服务器，而是浏览器

前面七个场景（SQL / XSS / 上传 / SSRF / 命令注入 / 文件包含 / 反序列化 / XXE / JWT）里，
攻击者都是**直接向服务器发请求**，服务器是受害者。

CSRF 不一样：

| | 直接攻击类漏洞 | CSRF |
|---|---|---|
| 攻击者需要能访问目标吗 | 需要 | **不需要** |
| 攻击者能读到响应吗 | 能 | **不能**（同源策略挡着） |
| 攻击者实际做了什么 | 构造恶意输入 | **让受害者的浏览器替他发请求** |

所以 CSRF 的形态是：

```
① 受害者登录了 bank.com，浏览器持有 bank.com 的 Cookie
② 受害者在同一个浏览器里打开了 attacker.com
③ attacker.com 的页面里有一个自动提交的表单，action 指向 bank.com
④ 浏览器提交表单 —— 并且**自动带上 bank.com 的 Cookie**
⑤ bank.com 收到一个「带着合法 Cookie 的正常请求」，照做
```

第 ⑤ 步是问题的核心：

> **服务器无法从请求本身分辨「这是用户自己点的，还是被别的页面骗着发的」。**

因为这两者在 HTTP 层面**完全一样**。

### 1.1 为什么浏览器要自动带 Cookie

这是 Cookie 的设计前提（RFC 6265）：Cookie 的作用域是**域名**，不是「谁发起的请求」。
浏览器认为「这是要发给 bank.com 的请求，那就该带上 bank.com 的 Cookie」。

这个设计在 Cookie 出现时是合理的（那时网页还不能跨站发请求），
后来 Web 变得复杂，它就成了一条需要靠应用层弥补的裂缝。

### 1.2 攻击者能做什么、不能做什么

浏览器会用**同源策略**划一条线：

| 攻击者的页面可以 | 攻击者的页面不可以 |
|---|---|
| 让浏览器发出任意请求（表单 / `<img>` / `fetch`） | 读取目标站点的响应内容 |
| 让请求自动带上目标站点的 Cookie | 读取目标站点页面里的内容 |
| 读到自己页面里的一切 | 拿到目标站点的任何数据 |

**这条线就是所有 CSRF 防护的基础**：

> 只要在请求里放一个「只有目标站点的页面才知道的值」，
> 攻击者就填不出来 —— 因为他读不到那个页面。

---

## 二、low 档：零防护

### 2.1 漏洞代码

```php
$state['email'] = $_POST['email'];
csrf_save($state);
// 就这些。没有 token、没有 Referer 检查、没有 Origin 检查。
```

### 2.2 利用

攻击者页面里一个自动提交的表单就够了：

```html
<form action="http://127.0.0.1:8080/csrf/low.php" method="POST">
  <input type="hidden" name="email" value="attacker@evil.example">
</form>
<script>document.forms[0].submit()</script>
```

受害者一打开这个页面，邮箱就被改掉了 —— 而他什么都不会察觉。

**用 curl 复现等价于浏览器提交表单：**

```bash
curl -X POST http://127.0.0.1:8080/csrf/low.php \
  -H "Referer: http://evil.example/attack.html" \
  -d "email=attacker@evil.example"
```

> 靶场把攻击者页面 `attacker.html` 放在同一个域下，是为了自包含。
> 这会让同源策略在演示时失效（同域下 JS 能读到响应），
> **但不影响结论** —— 真正决定 CSRF 能否成立的性质
> （请求里有没有带上跨站页面拿不到的东西）与页面放在哪里无关。

### 2.3 为什么改邮箱值得单独做成一个场景

改邮箱看起来不像「改密码」那么严重，但它是**账号接管的常见前置步骤**：

```
改邮箱 → 触发「忘记密码」→ 重置链接发到攻击者的邮箱 → 接管账号
```

也就是说，CSRF 的危害取决于被攻击的接口，而不是这个漏洞本身「看起来有多严重」。
**一个没有任何来源校验的状态变更接口，就是一个账号接管的入口。**

---

## 三、medium 档：只检查 Referer

### 3.1 防护措施

```php
$host = $_SERVER['HTTP_HOST'];
$referer = $_SERVER['HTTP_REFERER'];

if ($referer === '') {
    $allow = true;                                  // ← 绕过点一
} elseif (strpos($referer, $host) !== false) {
    $allow = true;                                  // ← 绕过点二
} else {
    $allow = false;
}
```

思路是「看请求是从哪个页面发出来的」。但这段代码有两个独立的问题。

### 3.2 绕过一：Referer 是「客户端自愿提供的」

代码里那个 `$referer === '' → 放行`，隐含的假设是：

> 攻击者没法不发 Referer。

**这个假设是错的。** 攻击者控制着自己页面的 HTML，当然也能控制浏览器发不发 Referer：

```html
<meta name="referrer" content="no-referrer">
```

加了这一行，从该页面发出的所有请求都**完全不带 Referer** —— 检查直接走进放行分支。

所以「空 Referer 放行」不是兼容性处理，而是一个**完整的绕过**：

```bash
# 不带 Referer 的请求 —— 等价于攻击页面加了 no-referrer
curl -X POST http://127.0.0.1:8080/csrf/medium.php -d "email=attacker@evil.example"
```

> 一句话概括：
> **Referer 属于「请求方可以自愿提供、也可以自愿不提供」的信息，
> 服务端不能把它当作强制性的证据。**

### 3.3 绕过二：子串匹配没有边界

`strpos($referer, $host) !== false` 判断的是「**包含**」，不是「**相等**」。

于是真实场景里：

```
目标站点：  bank.com
攻击者注册：bank.com.evil.com
浏览器填的 Referer（诚实的）：http://bank.com.evil.com/attack.html
                                 ↑ 里面确实包含 "bank.com"
strpos 检查：通过
```

**注意这个绕过不需要伪造任何请求头。**
攻击者只是买了个域名，浏览器诚实地填上了真实的 Referer，检查却通过了。

这个「包含 vs 相等」的错误在整个靶场里反复出现：

| 场景 | 用「包含」代替「相等」的地方 |
|---|---|
| SSRF | 黑名单里有 `127.0.0.1`，但 `localhost` 不在（漏项）；反过来 `127.0.0.1` 的写法有几十种 |
| 命令注入 | 黑名单里有 `;`，但没有 `&` |
| XXE | 过滤请求体里的 `<!ENTITY`，但「请求体」不等于「文档的所有输入」 |
| **CSRF** | **`strpos($referer, $host)` 不要求 host 是域名边界** |

根本原因都一样：

> **用「出现了某个片段」代替了「它就是这个东西」。**

### 3.4 为什么 Referer 检查本质上不该当主防线

就算把上面两个问题都修好（要求 Referer 严格等于本站页面地址），
它仍然有天然缺陷：

- **Referer 可能被隐私设置、代理、企业策略剥掉** —— 正常用户会被误伤
- **HTTPS → HTTP 的跳转不会带 Referer**（浏览器不向下传递来源）
- **`Referrer-Policy` 由发送方决定** —— 而发送方（攻击者）不配合

**结论：Referer / Origin 只能作为「额外的信号」，不能单独承担防线。**

---

## 四、high 档：token

### 4.1 修复代码

```php
// ① token 校验（会话绑定 + 定长比较）
if (!hash_equals($state['token'], $receivedToken)) { /* 拒绝 */ }

// ② 用过即换
$state = csrf_rotate_token($state);

// ③ Referer 只作为额外信号
if ($referer !== '' && strpos($referer, $host) === false) { /* 拒绝 */ }
```

### 4.2 token 为什么有效

因为它放在一个**攻击者读不到的地方**：

```
① 服务端生成随机值，通过本站页面渲染到表单的隐藏字段里
② 攻击者的页面读不到那个字段（同源策略）
③ 提交时必须带上它 —— 攻击者填不出来
```

回到第一节那张表：攻击者的页面**能发请求**，但**读不到内容**。
token 正好卡在这条线的两侧。

### 4.3 ⚠️ 一个最容易搞错的地方：token 不能放在 Cookie 里

如果 token 放在 Cookie 里，浏览器会**自动携带**它 ——
那么攻击者发起的跨站请求**也会自动带上**，token 就完全失效了。

> **token 必须放在请求体或查询参数里，也就是「需要页面主动填进去」的位置。**

判断标准很简单：

> **问一句「浏览器会不会自动带上它？」**
> 会 → 它挡不住 CSRF；不会 → 它才有意义。

这也是为什么「用 Cookie 存 CSRF token」是常见的错误实现。

### 4.4 层 ② 的取舍：用过即换

成功之后轮换 token，能顺带挡住「重放同一个请求」。

需要说明的是：**它不是防 CSRF 的必需品**。
不轮换的 token 同样能挡住跨站请求（因为攻击者读不到它）。
轮换解决的是另一个问题 —— 同一个合法请求被反复提交。

本档把它做出来，是为了展示「一个防护点顺带解决了另一类问题」的情况。

### 4.5 层 ④：真正可靠的兜底在业务层

再强的 CSRF 防护，都不如**让这个操作本身不容易被滥用**：

| 操作 | 业务层兜底 |
|---|---|
| 改邮箱 | 要求输入原密码；或向旧邮箱发确认链接 |
| 改密码 | 必须输入原密码 |
| 转账 | 二次验证 / 短信验证码 |
| 删除数据 | 输入要删除的对象名字确认 |

这样即使 CSRF 拿到了请求，也**改不成**。

**这一层不是「多此一举」** —— 它是唯一不依赖浏览器行为的防护。

### 4.6 现代浏览器的 `SameSite`

给会话 Cookie 加上 `SameSite=Lax`（或 `Strict`），
现代浏览器就会阻止跨站请求携带这个 Cookie —— CSRF 从根上失效。

但要清楚它的边界：

- 它是**浏览器层面的兜底**，不是应用层防护的替代品
- `Lax` 仍允许**顶级导航**（点击链接）携带 Cookie
- 老浏览器 / 某些客户端不支持
- 有些场景确实需要 `SameSite=None`（跨站嵌入）

所以：**该加，但不能只靠它。**

---

## 五、其他值得知道的手法

### 5.1 GET 型状态变更

```html
<img src="http://bank.com/change_email?to=attacker@evil.example">
```

不需要表单、不需要 JavaScript，一个图片标签就够了。

所以有一条硬性约定：

> **状态变更必须用 POST**（更准确地说是「不能被 GET 触发」）。
> 不是因为 POST 更安全（它同样能被 CSRF），
> 而是因为 GET 的触发门槛低到「一张图片」「一个链接预览」都能做到。

### 5.2 `enctype` 技巧

有些接口只接受 JSON（`Content-Type: application/json`），
表单发不出这个类型 —— 于是被认为「天然免疫 CSRF」。

但 `enctype="text/plain"` 的表单可以构造出「看起来像 JSON」的请求体：

```html
<form action="http://bank.com/api/transfer" method="POST" enctype="text/plain">
  <input name='{"to":"attacker","amount":1000,"x":"' value='"}'>
</form>
```

发出的是 `{"to":"attacker","amount":1000,"x":""}` 这种形状。
**「只接受 JSON」不等于「免受 CSRF」。** 必须校验 `Content-Type`。

### 5.3 XSS + CSRF 的组合

XSS 比 CSRF 更强 —— 因为 XSS 能**读到页面内容**，
所以能直接拿到 CSRF token，之后想发多少请求都行。

**这也是一个设计原则**：CSRF token 的目的是「限制攻击者不能凭空构造请求」，
它不负责抵挡 XSS。**能读到页面内容的攻击者，token 挡不住。**

### 5.4 与「登录 CSRF」的区别

还有一种容易被忽略的情况：**登录接口本身也能被 CSRF**。

攻击者用自己的账号登录，然后把登录请求「转嫁」给受害者 ——
受害者浏览器里就变成了攻击者的会话，
之后他输入的所有数据都进了攻击者的账号。

防御方式：登录时也带 token，或者登录成功后轮换会话 ID。

---

## 六、防御清单

| 优先级 | 做法 | 说明 |
|---|---|---|
| **①** | **CSRF token** | 服务端生成随机值，**只通过本站页面渲染**，请求体提交 |
| **①** | **token 不能放 Cookie** | 自动携带 = 白送。一句话判据：「浏览器会自动带上它吗？」 |
| **①** | **token 绑定会话** | 否则攻击者能拿自己的 token 骗别人 |
| **①** | **敏感操作二次确认** | 原密码 / 邮件确认 —— 唯一不依赖浏览器行为的防护 |
| **②** | 状态变更**不用 GET** | `&lt;img&gt;` 就能触发，门槛太低 |
| **②** | `hash_equals()` 比较 token | 防时序侧信道 |
| **②** | 校验 `Content-Type` | 挡住 `enctype="text/plain"` 那类构造 |
| **③** | `SameSite=Lax/Strict` | 浏览器层兜底，不能只靠它 |
| **③** | Referer / Origin 检查 | **只能作为补充**，不能单独承担防线 |
| **③** | 成功之后轮换 token | 顺带防重放 |

按有效性排序：**① ≫ ② > ③**。

最需要记住的一条：**「我检查了 Referer」不是修复**。
medium 档就是为了说明这件事 —— 攻击者可以主动不发 Referer，
也可以让一个「名字里含目标域名」的自己人域名把 Referer 带出来，
而后者甚至不需要任何技术手段，只要买一个域名。

---

## 七、和本靶场其他场景的联系

### 7.1 「依赖了攻击者能控制的信息」

这是靶场里第五次出现这个结构：

| 场景 | 依赖的信息 | 为什么不可靠 |
|---|---|---|
| SSRF | 输入里的字符串 | 同一个地址有无数种写法 |
| 命令注入 | 输入里的分隔符 | 黑名单列不全 |
| 反序列化 | 字符串里的类名 | 大小写不一致 |
| XXE | 请求体里的文本 | 实体声明可以在文档之外 |
| **CSRF** | **Referer** | **客户端可以自愿不发，域名可以自愿包含** |

共同点：

> **防护所依赖的东西，如果是请求方可以自由决定的，那它就挡不住请求方。**

反过来说，CSRF token 之所以有效，正是因为它**不是请求方能决定的** ——
它由服务端生成、只通过攻击者读不到的通道传递。

### 7.2 与 XSS 的关系：互为镜像

| | XSS | CSRF |
|---|---|---|
| 攻击者的立足点 | **目标站点的页面里** | **自己的站点里** |
| 能读目标站点响应吗 | 能（因为就在目标域名下） | 不能（同源策略） |
| 需要用户做什么 | 访问被注入的页面 | 访问攻击者的页面 |
| 防御的边界 | 输出编码 / CSP | token / SameSite |

有意思的是：**XSS 能绕过所有 CSRF 防护**（因为它能读到 token），
而 CSRF 防护对 XSS 完全无用。两者的防御手段也几乎不重叠。

### 7.3 与 JWT 的联系：token 的存放位置

两个场景都涉及 token，但含义完全不同：

| | JWT（认证 token） | CSRF token |
|---|---|---|
| 存在哪 | 请求头 / Cookie | **只能放请求体** |
| 谁能读到 | 客户端（本来就要给客户端用） | **只有本站页面** |
| 失效意味着 | 身份被冒充 | 能凭空构造请求 |

**同一个词「token」，在两个场景里的安全属性是相反的** ——
JWT 就是要给客户端用，而 CSRF token 恰恰不能让攻击者拿到。
混淆这两者（比如把 CSRF token 也塞进 JWT 里，或者把 JWT 放在 Cookie 里却不加 SameSite）是常见错误。

---

## 八、延伸阅读

- [OWASP: Cross-Site Request Forgery](https://owasp.org/www-community/attacks/csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN: Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) —— `no-referrer` 是绕过 Referer 检查的正规手段
- [MDN: SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [RFC 6265 - HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/rfc6265) —— Cookie 作用域是按域名而不是按「谁发起的请求」
