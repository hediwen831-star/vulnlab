# XSS（跨站脚本）完整 Writeup

对应场景：`html/xss/low.php` / `medium.php` / `high.php`

本档所有载荷均经过实测。

---

## 一、原理：和 SQL 注入是同一个根因

初学者常把 XSS 和 SQL 注入当成两个不相干的知识点。其实它们的根因完全一样：

```
SQL 注入：用户输入 → 被数据库当成【SQL 语法】解析
XSS     ：用户输入 → 被浏览器当成【HTML 语法】解析
```

**数据被放进了代码的位置。** 区别只是解析器不同 —— 一个是数据库，一个是浏览器。

理解这一点之后，修复思路也就顺理成章了：

| | 修复手段 | 本质 |
|---|---|---|
| SQL 注入 | 参数化查询 | 改变**数据传递方式** |
| XSS | 输出编码 | 改变**数据表示形式** |

两者都是为了让数据**待在数据的位置上**，不参与语法解析。

### 为什么浏览器会"相信"服务端返回的内容

关键认知：**浏览器无法区分「服务端自己写的 HTML」和「用户输入被拼进去的 HTML」。**

从浏览器的视角看，它收到的就是一整块 HTML 文档，那是可信的页面代码。
至于其中哪一段来自数据库、哪一段来自用户，浏览器根本无从得知 ——
也不该由它来判断。

所以责任完全在服务端：**你拼进去的东西，就等同于你写的代码。**

---

## 二、三种类型（本靶场实现的是反射型）

| 类型 | 触发方式 | 数据流向 | 典型场景 |
|---|---|---|---|
| **反射型** | 用户点链接即触发 | 请求 → 服务端拼接 → 立即返回 | 搜索框、错误提示、跳转页 |
| **存储型** | 攻击者先存，受害者后看 | 请求 → **存库** → 其他用户访问时输出 | 留言板、评论、用户昵称 |
| **DOM 型** | 完全在浏览器端发生 | 请求 → **前端 JS 处理** → 写入 DOM | `innerHTML` / `document.write` |

**危害排序：存储型 > 反射型 > DOM 型**（存储型不需要诱导点击，可批量影响用户）。

本项目三档实现的是**反射型**，因为它最容易观察：一次请求就能看到完整的因果关系。
但修复手段（输出编码）对三种类型都适用。

---

## 三、low 档：无防护

### 3.1 观察输出点

页面提供了两个视角的对照，这是本档最重要的信息：

```
① 服务端拼接出的 HTML（源代码视角）
   <div class="greeting">欢迎回来，<script>alert(1)</script>！</div>

② 浏览器实际解析的结果
   —— 弹出对话框
```

**① 和 ② 长得不一样的位置，就是漏洞发生的位置。**

源头 ① 里，你的输入是一段"文本"；但浏览器拿到 ② 之后，
它看到 `<script>` 这四个字符，就认为"这里开始是一段要执行的代码"。

### 3.2 最小验证载荷

```
?name=<script>alert(document.domain)</script>
```

用 `document.domain` 而不是 `alert(1)`：它证明了**当前页面的上下文已经被控制**，
这是后续所有利用（读 Cookie、发起请求、篡改页面）的前提。

### 3.3 为什么它一定能执行

因为服务端做的是**字符串拼接**：

```php
$output = '<div class="greeting">欢迎回来，' . $name . '！</div>';
```

拼接之后，服务端自己也没法区分哪部分是自己写的、哪部分来自用户 ——
它交给浏览器的就是一个完整的字符串。**浏览器只能照单全收。**

---

## 四、medium 档：黑名单过滤与绕过

### 4.1 防护措施

```php
$blacklist = ['<script', '</script', 'javascript:'];
$filtered  = str_ireplace($blacklist, '', $name);
```

看起来很合理：堵住了 script 标签和 `javascript:` 伪协议。

### 4.2 关键认知：黑名单堵不完

能触发脚本执行的写法是一个**组合空间**，不是一份清单：

```
触发点 = 标签 × 事件属性 × 编码方式 × 解析差异
```

- **标签**：`script` / `img` / `svg` / `iframe` / `a` / `body` / `details` / `marquee` / …
- **事件属性**：`onerror` / `onload` / `onfocus` / `onmouseover` / `onanimationstart` / …
- **编码方式**：大小写 / HTML 实体 / URL 编码 / Unicode / 空字节 / …
- **解析差异**：浏览器的容错解析、SVG 与 MathML 的命名空间、…

而黑名单只能列出**作者想到的那几种**。

这和 SQL 注入完全同构：**黑名单在原理上必然失败，
因为要枚举的是一个无穷集合。**

### 4.3 绕过一：换个标签（本档最直接的打法）

不使用 `<script>`，改用任意标签 + 事件属性：

```
?name=<img src=x onerror=alert(1)>
```

拆解一下这个载荷为什么有效：

| 部分 | 作用 |
|---|---|
| `<img` | 任意标签，黑名单里没有 |
| `src=x` | 故意指向一个不存在的资源 |
| `onerror=alert(1)` | 加载失败时触发 —— **浏览器会自动执行** |

**关键点：`onerror` 的触发不需要用户做任何事** —— `src=x` 加载失败是必然的，
所以这段代码在页面加载时就会执行。

同类载荷：

```
<svg onload=alert(1)>
<body onpageshow=alert(1)>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
```

### 4.4 绕过二：嵌套（利用单次替换）

`str_ireplace` 是**单次非递归**替换：扫描一次原串、删除匹配项、**不重新扫描结果**。

```
输入:      <scr<script>ipt>alert(1)</script>
扫描:      删掉中间的 "<script"
结果:      <script>alert(1)</script>     ← 又拼回来了
```

这个性质和 SQL 注入里 `ununionion → union` 的**双写绕过是同一个机制**。

### 4.5 其他常见绕过手法（同一漏洞的不同打法）

| 手法 | 示例 | 为什么有效 |
|---|---|---|
| 大小写混合 | `<ScRiPt>` | 用 `str_replace`（区分大小写）而非 `str_ireplace` 时直接通过 |
| 不用标签 | `<img onerror=…>` | 黑名单根本没有覆盖 |
| 嵌套 | `<scr<script>ipt>` | 单次替换后拼回原词 |
| 编码 | `%3Cscript%3E` | 过滤发生在解码之前 |
| 伪协议变体 | `<a href="javas&#99;ript:alert(1)">` | HTML 实体会被浏览器解码 |
| 空字节截断 | `<scri%00pt>` | 某些旧解析器的处理缺陷 |

### 4.6 验证

```
?name=<img src=x onerror=alert(1)>
```

页面上的「过滤后」那一行会显示：**输入没有被改动**（因为不含黑名单词），
然后 ② 视图里弹窗 —— 过滤器完全没起作用。

---

## 五、high 档：输出编码

### 5.1 修复代码

```php
$safeName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$output   = '<div class="greeting">欢迎回来，' . $safeName . '！</div>';
```

三个参数都不是随便加的：

| 参数 | 作用 | 不加会怎样 |
|---|---|---|
| `ENT_QUOTES` | 同时转义单引号和双引号 | 默认只转双引号；属性用单引号包裹时可被逃逸 |
| `ENT_SUBSTITUTE` | 非法 UTF-8 序列用替代字符 | 默认返回**空字符串**，构造的非法编码能让整个输出消失 |
| `'UTF-8'` | 显式指定字符集 | **不指定是危险的** —— 宽字节字符集下转义可能被绕过（历史上真实出现过） |

### 5.2 为什么这样有效

`htmlspecialchars` 把语法字符变成实体：

```
<  →  &lt;
>  →  &gt;
"  →  &quot;
'  →  &#039;
&  →  &amp;
```

浏览器看到 `&lt;` 时，它解析的结果是一个**要显示的字符** `<`，
而不是"标签开始"。**数据回到了数据的位置上。**

页面上的 ① ② 两个视图现在长得一样了 —— 这就是修复生效的直接证据。

### 5.3 ⚠️ 最重要的一节：编码必须匹配上下文

**用了 `htmlspecialchars` 仍被 XSS 的头号原因，就是编码方式没有匹配输出位置。**

| 输出位置 | 需要的处理 | 错误做法的后果 |
|---|---|---|
| `<div>值</div>` | `htmlspecialchars` | — |
| `<div title="值">` | `htmlspecialchars` + `ENT_QUOTES` | 属性被闭合，注入新属性 |
| `<script>var a = "值"</script>` | **不能**用 HTML 编码，需要 `json_encode` 并转义 `</script>` | HTML 实体在 JS 里不会被解码，但 `</script>` 会提前结束脚本块 |
| `<a href="值">` | `urlencode` + **协议白名单** | `javascript:alert(1)` 仍然可执行 |
| `<div class=值>`（无引号） | 转义救不了，**必须加引号** | 空格即可逃逸出属性 |
| `style="值"` / CSS 内 | CSS 编码，且应禁止用户控制样式 | `expression()` 等历史手法 |

**记住一句话：输出编码不是「把危险字符换掉」，而是「按当前语法的规则转义」。**

---

## 六、纵深防御（修复之外的补充）

输出编码是**根治手段**，但真实系统里还需要几层保险：

### 6.1 HttpOnly Cookie

```
Set-Cookie: sessionid=xxx; HttpOnly; Secure; SameSite=Lax
```

作用是**限制 XSS 的后果**：即使 XSS 发生，JS 也读不到会话 Cookie。
这把攻击从「直接接管账号」降级为「钓鱼 / 篡改页面」。

### 6.2 Content-Security-Policy

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```

CSP 是**兜底**：即使某处漏了转义，内联脚本也会被浏览器拒绝执行。

**但要注意**：CSP 不能替代输出编码。有 `unsafe-inline` 或存在 JSONP 端点时，
CSP 的保护会大幅削弱。它是保险，不是解决方案。

### 6.3 其他

- **输入校验**（白名单）：对邮箱、电话这类有明确格式的字段，从源头卡住
- **富文本场景**：不能用简单转义（那会把格式也转掉），需要**专门的 HTML 净化库**
  （如 DOMPurify），并且用「允许哪些」的白名单模式
- **前端框架**：Vue / React 默认转义插值，但要小心
  `v-html` / `dangerouslySetInnerHTML` 这类逃生舱
- **DOM 型 XSS**：避免 `innerHTML` / `document.write` / `eval`，
  改用 `textContent` / `createElement`

---

## 七、防御清单

**应做**

- 所有输出到 HTML 的数据都经过上下文匹配的编码
- htmlspecialchars 必须带 ENT_QUOTES + ENT_SUBSTITUTE + 显式字符集
- 属性值必须加引号（转义救不了无引号属性）
- Cookie 加 HttpOnly / Secure / SameSite
- 配置 CSP，禁止内联脚本
- 富文本用专门的净化库 + 白名单
- 前端避免 innerHTML / document.write，改用 textContent
- 在模板层做统一转义（让「忘记转义」这件事变难）

**不应做**

- 依赖黑名单过滤标签/关键字
- 在输入阶段「洗数据」（同一份数据可能有多种输出上下文）
- 以为「前端已经校验过了」就安全（请求可以被直接构造）
- 以为「只输出到自己的页面」就没事（存储型 XSS 影响的是其他用户）
- 用 CSP 替代输出编码


---

## 八、延伸阅读

- OWASP Top 10 A03:2021 — Injection（XSS 归属此类）
- OWASP Cross Site Scripting Prevention Cheat Sheet（含完整的上下文对照表）
- OWASP DOM based XSS Prevention Cheat Sheet
- 《XSS 跨站脚本攻击剖析与防御》—— 中文资料里最系统的一本

**与 SQL 注入的对照阅读**：把本文件和 `sqli.md` 并排看，
会发现「黑名单必败」「数据不能参与语法解析」这两条结论在两处完全一致 ——
**这是同一个安全原则在不同解析器上的投影。**
