# 文件上传漏洞 Writeup

对应场景：`html/upload/low.php` / `medium.php` / `high.php`

**本场景的危险性高于其他场景**：文件上传漏洞被利用后通常直接等于服务器失陷。
请只在本地靶场练习。

---

## 一、为什么这个漏洞特别危险

其他漏洞的危害通常是「读到不该读的数据」；
文件上传漏洞的危害是「**在服务器上执行任意代码**」。

一旦攻击者能上传并访问一个 `.php` 文件，他就拿到了一个 webshell ——
可以读写文件、连数据库、内网横向、留后门。从「一个洞」变成「整台机器」。

这也是为什么它常被单独列为一类高危漏洞，而不是简单归到「配置错误」里。

---

## 二、low 档：零校验 + 原名保存

### 2.1 漏洞代码

```php
$target = UPLOAD_DIR . '/' . $file['name'];      // 用户给什么名字就用什么
move_uploaded_file($file['tmp_name'], $target);  // 也不检查内容
```

**两个独立错误叠加**：

| 错误 | 后果 |
|---|---|
| 不校验类型 | 任何文件都能传，包括可执行脚本 |
| 用用户提供的文件名 | 攻击者控制了文件在服务器上的**后缀** |

只需要有其中任何一个都不至于直接失陷：
- 校验了类型 → 传不了脚本
- 重命名了 → 传上来的脚本没有可执行后缀

**两个同时存在，就是 getshell。**

### 2.2 完整利用链

**步骤一：准备一个最小的脚本**

```php
<?php echo "VULNLAB_UPLOAD_MARKER"; ?>
```

真实场景里这一步会是一个功能完整的 webshell（如中国菜刀 / 冰蝎的载荷），
本靶场用回显标记串代替。

**步骤二：上传**

```bash
curl -F "file=@shell.php" http://127.0.0.1:8080/upload/low.php
```

页面会显示「上传成功」以及可访问地址 `/uploads/shell.php`。

**步骤三：访问，触发执行**

```bash
curl http://127.0.0.1:8080/uploads/shell.php
# → VULNLAB_UPLOAD_MARKER
```

**这一步是整个漏洞的核心 —— 服务器真的执行了你上传的代码。**

### 2.3 为什么能执行

两个条件同时满足：

1. 文件落到了**Web 可访问目录**下（`html/uploads/`）
2. 该目录下的 `.php` 文件**会被 Web 服务器交给 PHP 解析器执行**

这也是修复时必须同时处理的两件事：让文件传不进来，以及就算传进来也不能执行。

---

## 三、medium 档：只信客户端声明的类型

### 3.1 漏洞代码

```php
$allowed = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($file['type'], $allowed, true)) {
    // 拒绝
}
```

看起来很合理 —— 只允许图片。问题在于 `$file['type']` 是什么。

### 3.2 `$_FILES['file']['type']` 的来源

它来自请求体里的 **multipart 分段头**：

```
------WebKitFormBoundaryXXX
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php          ← 就是这一行
                                          （浏览器填的，但请求可以手工构造）
------WebKitFormBoundaryXXX
<?php ...
------WebKitFormBoundaryXXX--
```

**这个值完全由客户端提供。** 浏览器比较诚实（按扩展名填），但 curl / Burp 可以随意设置。

服务端检查它，等于让攻击者自己声明「我是合法用户」然后放行。

### 3.3 利用：手工构造请求

**为什么浏览器打不通**：浏览器上传 `.php` 时会诚实地填 `Content-Type: application/x-php`，
被拦下。所以这个漏洞**必须手工构造请求** —— 这也让它比 low 档更接近真实渗透场景。

**用 curl**：

```bash
curl -F "file=@shell.php;type=image/jpeg" http://127.0.0.1:8080/upload/medium.php
#                           ^^^^^^^^^^^^^^^^^
#                           这一行完全由你决定
```

`-F` 的 `;type=` 参数用来覆盖 curl 默认填的 `application/octet-stream`。

**用 Burp**：开启拦截，在 multipart 分段头里把 `Content-Type` 改成 `image/jpeg`，放行。

**结果**：上传成功，访问 `/uploads/shell.php` 同样能执行。

### 3.4 关键教训

**永远不要相信客户端提供的任何元数据。**
Content-Type、文件名、文件大小、Referer、User-Agent ——
这些都在请求里，而请求是可以被完全控制的。

服务端要判断「这是什么文件」，唯一可靠的方式是**看文件内容本身**
（`getimagesize` / `finfo` / 文件头魔数）。

---

## 四、high 档：四层叠加防护

### 4.1 四层各自的职责

| 层 | 手段 | 挡住什么 | 单独使用的缺陷 |
|---|---|---|---|
| ① 后缀白名单 | `in_array(strtolower($ext), ALLOWED_EXT)` | 非图片后缀、大小写绕过 | 双后缀、解析漏洞 |
| ② 内容检查 | `getimagesize()` | 改后缀伪装的文件 | **图片马**（末尾追加 PHP 代码） |
| ③ 重命名 | `bin2hex(random_bytes(8))` | 攻击者控制文件名/后缀 | 内容仍是可执行脚本 |
| ④ 目录禁执行 | Web 服务器配置 | **兜底**：前 ③ 层全失效也执行不了 | 需要部署配置配合 |

### 4.2 为什么必须多层

**只有 ①**：`shell.php.jpg` 在某些 Apache 配置下会被当 PHP 解析；
`.phtml` / `.php5` / `.pht` 等后缀也可能被解析 —— 黑名单列不全，白名单也可能漏掉服务器支持的其他后缀。

**只有 ②**：**图片马**。在合法 PNG 末尾追加 `<?php system($_GET['c']); ?>`，
`getimagesize` 依然能通过（因为它只解析文件头）。此时如果目录能解析 PHP，
配合文件包含漏洞（LFI）就能执行。

**只有 ③**：文件名安全了，但传进来的仍是脚本，只是改名而已。

**只有 ④**：目录不解析了，但文件仍可能被其他方式利用（如作为 XSS 载体、
或通过其他漏洞读取）。

**前三条是「让别人传不进来可执行内容」，第四条是「就算传进来了也执行不了」。**
前者收敛攻击面，后者兜底 —— **安全设计里兜底永远不能省。**

### 4.3 关于第 ④ 层的诚实说明

**本靶场跑在 PHP 内置服务器（`php -S`）上，它不支持 `.htaccess`，
所以第 ④ 层在本靶场无法真实生效。**

但它是真实部署中最重要的一层，配置方式：

**Nginx**
```nginx
location ^~ /uploads/ {
    location ~ \.(php|php5|phtml|phar)$ { deny all; }
}
```

**Apache**（upload 目录下放 `.htaccess`）
```apache
php_flag engine off
RemoveHandler .php .phtml .php5
AddType text/plain .php .phtml .php5
```

**更彻底的做法**：把上传目录放到 **Web 根之外**，
通过应用层做鉴权后读取文件。这样连「能不能访问到」都不由文件系统决定。

### 4.4 代码里的几个细节

```php
$ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
```
**必须 `strtolower`** —— 在 Windows 这类不区分大小写的文件系统上，
不转换大小写的后缀校验形同虚设（`SHELL.PHP` 会被当成 `.php` 保存）。

```php
$safeName = bin2hex(random_bytes(8)) . '.' . $ext;
```
**用 `random_bytes` 而不是 `uniqid()` 或时间戳** —— 后者可预测，
攻击者能猜到文件名。这本身也是一类漏洞（可导致越权访问他人上传的文件）。

---

## 五、其他需要知道的绕过手法

| 手法 | 原理 | 防御 |
|---|---|---|
| 大小写 | `SHELL.PHP` | `strtolower` |
| 双后缀 | `shell.php.jpg` | 白名单 + 目录禁执行 |
| 解析漏洞 | Apache 多后缀、Nginx `%00`、IIS `;` | 升级服务器 + 目录禁执行 |
| 图片马 | 合法图片末尾追加代码 | 图片二次处理（重新编码） |
| `.htaccess` 上传 | 上传自定义 `.htaccess` 覆盖解析规则 | 禁止上传点开头的文件 |
| 条件竞争 | 先传临时合法文件、在删除前访问执行 | 上传到不可访问目录再校验 |
| Content-Type 伪造 | 改 multipart 分段头 | 检查文件内容而非声明 |

---

## 六、防御清单

**应做**

- 后缀白名单（而非黑名单），且必须 strtolower
- 检查文件真实内容（getimagesize / finfo），不信任 Content-Type
- 重命名（用不可预测的随机名），不让用户控制文件名
- 上传目录禁止执行脚本（Nginx/Apache 配置）
- 把上传目录放到 Web 根之外，通过应用层鉴权后读取        ← 最彻底
- 限制文件大小、上传频率
- 图片做二次处理（重新编码可彻底销毁图片马）
- 上传目录用独立域名或独立路径（隔离 Cookie 与同源策略）
- 文件名过滤路径分隔符（防目录穿越 ../）

**不应做**

- 相信 $_FILES['type']（客户端声明）
- 只用黑名单列后缀
- 用可预测的文件名（uniqid / 时间戳）
- 把上传目录和代码放在同一个可执行路径下
- 以为「前端限制了文件类型」就够了（请求可以手工构造）


---

## 七、与前面两个场景的联系

把三个场景放在一起看，会发现一条共同的主线：

```
SQL 注入   数据被当成 SQL 语法   → 修复：参数化（改变数据传递方式）
XSS        数据被当成 HTML 语法  → 修复：输出编码（改变数据表示形式）
文件上传   数据被当成可执行代码   → 修复：白名单 + 内容检查 + 禁执行（改变数据的存放与执行条件）
```

**都是「数据被当成了代码」，只是解析器不同**（数据库 / 浏览器 / PHP 引擎）。

而三者的防御思路也高度一致：**不要试图「过滤掉危险的东西」，而是让危险的东西失去意义。**

- SQL：参数化 → 危险内容永远只是「值」
- XSS：输出编码 → 危险内容永远只是「文本」
- 上传：目录禁执行 → 危险内容永远不会被「执行」

---

## 八、延伸阅读

- OWASP File Upload Cheat Sheet
- OWASP Top 10 A04:2021 — Insecure Design / A05:2021 — Security Misconfiguration
- 《Web 安全深度剖析》第 6 章
- 关于图片马的构造与检测：搜索「图片马制作 与 二次渲染绕过」
