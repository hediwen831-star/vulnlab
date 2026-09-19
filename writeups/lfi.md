# 文件包含（LFI / RFI）Writeup

> 对应场景：`html/lfi/low.php` / `medium.php` / `high.php`
>
> 本档所有载荷均经过实测（Windows + PHP 7.3 环境）。

---

## 一、原理：为什么它比「任意文件读取」高一个量级

`include` 干的事是**把指定文件读进来，当作 PHP 代码执行**。所以它同时具备两个能力：

| 能力 | 后果 |
|---|---|
| **读文件** | 能读到 Web 根之外的配置、私钥、系统文件 |
| **执行代码** | 只要文件内容是 PHP，就会被解析执行 |

后者是关键 —— 单纯的「任意文件读取」只能拿到数据，而文件包含能拿到**代码执行**。

### 完整攻击链

本靶场里就能拼出这条链：

```
① 文件上传 → 传一个「图片马」（内容是 PHP，但伪装成图片）
            ↓
② 文件包含 → include 那个上传的文件
            ↓
③ 代码执行 → getshell
```

这也是为什么修复文件上传时，除了「目录禁止执行脚本」，
还要保证**上传目录不被 include** —— 两者是配套的。

---

## 二、low 档：前缀固定下的路径穿越

### 2.1 漏洞代码

```php
$fullPath = __DIR__ . '/pages/' . $page;
include $fullPath;
```

### 2.2 利用

```
?page=../../config.php
```

`__DIR__` 是 `html/lfi/`，所以拼出来是：

```
html/lfi/pages/../../config.php   →   html/config.php
```

**注意一个细节**：`config.php` 被 include 时会被**当 PHP 执行** ——
所以页面上看到的不是源码，而是它的执行结果（定义了常量和函数，输出为空）。

这恰好说明「include 是执行而不是读取」—— 想读源码要用别的办法（见下）。

### 2.3 ⚠️ 本档的一个真实限制：伪协议用不了

因为路径**前面被固定拼了** `<绝对路径>/pages/`，
而 `php://` 必须在路径**最开头**才会被识别成协议。

这是真实 LFI 的常见形态（前缀写死、只控制后半段）——
能完整控制路径的 `include $_GET['page']` 反而少见。

**那种完整可控的形态下，攻击面大得多**：

```
?page=php://filter/convert.base64-encode/resource=config.php   ← 读源码（不执行）
?page=/etc/passwd                                              ← 绝对路径
?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+        ← 直接执行注入的代码
```

**`php://filter` 值得单独说**：它能把文件内容 base64 编码后返回，
于是**绕过了「被当代码执行」这一层**，读到未经解析的原始源码 ——
源码里往往有数据库密码、API key、以及能串出更多漏洞的线索。

---

## 三、medium 档：黑名单与双写绕过

### 3.1 防护措施

```php
$blacklist = ['../', '..\\'];

foreach ($blacklist as $bad) {
    if (strpos($filtered, $bad) !== false) {
        $filtered = str_replace($bad, '', $filtered);   // 单次替换
    }
}
```

### 3.2 绕过

```
?page=....//....//config.php
```

**推导过程**（这是本档的核心）：

```
输入:      ....//....//config.php
查找 ../  : 在 "....//" 里，第 2、3 个字符开始是 "../"
删除它    : 删掉后剩下 ".." + "/" = "../"     ← 拼回来了！
再查一次？: str_replace 只扫一遍，不会重新扫描结果
最终结果  : ../../config.php                  ← 穿越成功
```

### 3.3 和 SQL 注入的双写绕过是同一个机制

| 场景 | 过滤掉的词 | 双写输入 | 过滤后 |
|---|---|---|---|
| SQL 注入 | `union` | `ununionion` | `union` |
| 文件包含 | `../` | `....//` | `../` |

**共同的原理**：**「删除型过滤」只扫一遍，而删除动作本身可能把危险片段重新拼出来。**

这不是某个语言的特性，而是「用字符串替换做安全过滤」这个做法的固有缺陷。

---

## 四、high 档：白名单映射

### 4.1 修复代码

```php
const ALLOWED_PAGES = [
    'about'   => 'about.php',
    'contact' => 'contact.php',
    'help'    => 'help.php',
];

if (!isset(ALLOWED_PAGES[$page])) { /* 拒绝 */ }
include __DIR__ . '/pages/' . ALLOWED_PAGES[$page];   // 值是常量
```

**关键点：用户输入只被当作「键」来查表**，真正进入路径的是表里写死的常量。

### 4.2 为什么白名单在这里是唯一正确的选择

回顾前两档的失败模式：

```
low    ：完全拼接     → 攻击者控制完整路径
medium ：黑名单       → 试图枚举「危险的路径写法」
```

而**「危险写法」是无穷集合**：

```
相对路径  ../  ..\
绝对路径  /etc/passwd  C:\Windows\win.ini
URL 编码  %2e%2e%2f
双写      ....//
大小写    PHP://
伪协议    php://  file://  data://  expect://  phar://  zip://  compress.zlib:// ...
平台差异  Windows 用 \ 和 /，Linux 只用 /
```

**但换到白名单视角，问题瞬间简单了**：

> 这个页面本来就只该加载那三个文件 —— 别的都不该被加载。

所以修复思路不是「想办法过滤掉坏的」，而是「只允许好的」。

### 4.3 第 ③ 层：越界兜底

```php
$realBase = realpath(__DIR__ . '/pages');
$realTarget = realpath($resolvedPath);
$insideBase = strpos($realTarget, $realBase . DIRECTORY_SEPARATOR) === 0;

if (!$insideBase) { /* 阻止 */ }
```

这一层看起来多余（白名单已经够了），但它防的是**「白名单表被人改坏」**：

万一有人为了加新页面，往表里写了个 `'evil' => '../../etc/passwd'`，
这层检查能兜住。**安全设计里兜底永远不能省** ——
这和文件上传场景的第 ④ 层（目录禁执行）、
SSRF 场景的第 ③ 层（用校验过的 IP 请求）是同一个思路。

---

## 五、其他值得知道的手法

| 手法 | 说明 | 前提 |
|---|---|---|
| `php://filter` | 读源码（base64），绕过「被当代码执行」 | 能控制路径开头 |
| `php://input` | 把 POST body 当文件包含 → 直接执行 | `allow_url_include=On`（默认 Off） |
| `data://` | 把 payload 内联在 URL 里 | 同上 |
| `/proc/self/environ` | 从环境变量读（可能含密钥） | Linux + 能读 proc |
| 日志投毒 | 把 PHP 代码写进 access log，再包含它 | 有日志写权限 |
| `phar://` | 反序列化利用（和 PHP 反序列化场景联动） | 有 `.phar` 文件可控 |
| 会话文件 | 把 payload 写进 session，包含 `/tmp/sess_xxx` | 会话文件路径可预测 |

**`php://input` / `data://` 需要 `allow_url_include=On`** ——
PHP 默认是 `Off`，所以现代环境里这两条大多不可用。
但 `php://filter` **不受这个配置影响**，这也是它最常用的原因。

---

## 六、防御清单

```
✅ 用白名单映射（最彻底）—— 用户输入只作为「键」查表
✅ 真要拼接时用 basename() 剥掉目录部分
✅ 用完 realpath() 做越界兜底（防白名单表被改坏）
✅ 禁止伪协议：allow_url_include = Off（PHP 默认）
✅ 上传目录也要禁止被 include（不只是禁止执行）
✅ 限制 open_basedir（PHP 配置层，把文件访问限制在指定目录内）

❌ 不要用黑名单过滤 ../（危险写法是无穷的）
❌ 不要只过滤 ../ 而不处理 ..\（Windows 分隔符）
❌ 不要以为「加了后缀 .php」就安全（伪协议和 %00 都能绕）
❌ 不要依赖 allow_url_include=Off 挡住 php://filter（挡不住）
```

---

## 七、和本靶场其他场景的联系

文件包含是**连接性最强的场景** —— 它和三个已有场景都能组合：

| 组合 | 效果 |
|---|---|
| 文件包含 + 文件上传 | 上传图片马 → include 它 → **getshell** |
| 文件包含 + 任意文件读 | 读 config → 拿数据库密码 → 横向 |
| 文件包含 + PHP 反序列化 | 用 `phar://` 触发反序列化（POP 链） |

**这也是真实渗透里的常见思路**：单个漏洞的危害有限，
但把两三个组合起来，往往就能从「读到一个文件」变成「拿下服务器」。

---

## 八、延伸阅读

- OWASP Testing Guide — Testing for Local File Inclusion
- OWASP Testing Guide — Testing for Remote File Inclusion
- PHP 手册：`php://` 包装器（完整的伪协议列表）
- 《PHP 安全之道》第 4 章
