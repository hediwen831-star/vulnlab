# PHP 反序列化（POP 链）Writeup

> 场景目录：`html/unserialize/` · 机读 PoC：`pocs/vulnlab-php-unserialize-pop-chain.yaml`
> CI 断言：7 条（见 `tests/verify_lab.py`）

---

## 一、原理：为什么它比「代码注入」更隐蔽

前面几个场景的漏洞点是**一行可疑的代码** —— 拼接 SQL、拼接 shell 命令、拼接待包含的路径。
反序列化不一样：**那一行代码看起来完全无害**。

```php
$obj = unserialize($data);   // 就这一行
```

它没有拼接、没有执行、没有输出。单独审这一行，看不出任何问题。

问题出在**它的能力**上。`unserialize()` 接收的字符串里携带了两样东西：

| 字符串里的内容 | 攻击者获得的能力 |
|---|---|
| 类名（`O:5:"Cache":`） | 决定**实例化哪个类** |
| 属性名与属性值 | 决定**这个对象的每个字段是什么** |

也就是说，攻击者可以凭空构造一个**他从未创建过、也无法通过正常业务逻辑创建的对象**，
并把它的每一个属性指定成任意值。

剩下的就交给魔术方法了 —— 那些「在特定时机自动执行」的方法。
其中 `__destruct` 最特殊：**对象被销毁时触发**，而 `unserialize()` 出来的对象
在脚本结束时就一定会被销毁。

> 所以在这个场景里，攻击者不需要诱导任何功能被调用。
> **反序列化这个动作本身，就是触发。**

### 完整攻击链

```
攻击者构造序列化字符串
        │
        ├─ 指定类名 Cache ────────────► 实例化 Cache
        │
        ├─ 指定 $key / $value ────────► 控制写入的内容
        │
        └─ 指定 $store 为 FileStore ──► 控制"往哪里写、用什么方法写"
                    │
                    ▼
        脚本结束 → Cache::__destruct() 自动执行
                    │
                    ▼
        调用 $store->write($key, $value)
                    │
                    ▼
        FileStore::write() 拼接 $dir . $key 并落盘
```

链上的三个环节：**一个自动触发的入口（`__destruct`）→ 一个可控的属性（`$store`）
→ 一个危险的终点（`file_put_contents`）**。
POP 链的构造就是找这三样东西并把它们串起来。

---

## 二、low 档：完全放开

### 2.1 漏洞代码

```php
$obj = @unserialize($data);   // 用户输入直接进来，没有任何约束
```

### 2.2 先读懂格式

PHP 序列化的格式本身不难，只是**长度必须自己数**：

```
O:<类名字节数>:"<类名>":<属性个数>:{ 键;值; 键;值; ... }

字符串:  s:<字节数>:"<内容>";
整数:    i:42;
布尔:    b:1;
空值:    N;
```

注意长度是 **字节数**，不是字符数 —— 纯 ASCII 时两者相同，
一旦掺进中文就会差出好几字节，整串立刻报废。这是手工构造时最常见的失败原因。

### 2.3 三个类，分别是链的哪个环节

| 类 | 关键方法 | 在链中的角色 |
|---|---|---|
| `Cache` | `__destruct()` → 调 `$store->write($key, $value)` | **入口**：自动触发 |
| `FileStore` | `write($key, $value)` → `file_put_contents($this->dir . $key, $value)` | **终点**：写文件 |
| `Logger` | `__toString()` → 拼接 `$prefix` 和 `$subject` | 备用节点 |
| `SafeNote` | 无危险方法 | 对照组 |

`Cache` 的 `$store` 属性就是链的**接头** —— 它没有类型约束，可以塞任何对象进去。

### 2.4 构造 payload

最省事的办法是**本地跑一遍 PHP**：

```php
require 'html/unserialize/classes.php';

$c = new Cache();
$c->key   = 'pop.txt';
$c->value = 'VULNLAB_POP_CHAIN_OK';
$c->store = new FileStore();
$c->store->dir = '../uploads/';

echo serialize($c);
```

输出：

```
O:5:"Cache":3:{s:3:"key";s:7:"pop.txt";s:5:"value";s:20:"VULNLAB_POP_CHAIN_OK";s:5:"store";O:9:"FileStore":1:{s:3:"dir";s:11:"../uploads/";}}
```

> **这不算作弊**。真实攻击里，攻击者拿到源码后干的就是这件事：
> 把类定义抠出来，本地生成 payload 再打过去。
> 手工拼串反而容易在长度上翻车。

逐段对照格式说明：

```
O:5:"Cache":3:{                     ← 实例化 Cache，它有 3 个属性
  s:3:"key";   s:7:"pop.txt";       ← $key = "pop.txt"
  s:5:"value"; s:20:"VULNLAB_POP_CHAIN_OK";
  s:5:"store";                      ← $store =
    O:9:"FileStore":1:{             ←   一个 FileStore 对象
      s:3:"dir"; s:11:"../uploads/";
    }
}
```

把这一串 POST 给 `low.php`，`uploads/` 下就多出了 `pop.txt`。

### 2.5 为什么 `$dir` 是 `../uploads/` 而不是 `uploads/`

这是本档实际调试时花掉最多时间的一个点，值得单独说。

链的终点是：

```php
$target = $this->dir . $key;
file_put_contents($target, $value);
```

**相对路径按进程的「当前工作目录」解析**，而 CWD 是什么取决于 PHP 怎么跑起来的。
实测（在 `html/` 和 `html/unserialize/` 各放一个打印 `getcwd()` 的探针脚本）：

| 请求的脚本 | `getcwd()` 返回 |
|---|---|
| `/probe.php`（在 `html/` 下） | `.../vulnlab/html` |
| `/unserialize/probe.php` | `.../vulnlab/html/unserialize` |

**PHP 内置服务器会把 CWD 切到「被请求脚本所在目录」。**
所以 `low.php` 运行时的 CWD 是 `html/unserialize/`，
从这里走到 `html/uploads/` 要写 `../uploads/`。

而这件事最麻烦的地方在于**它会静默失败**：

```php
return @file_put_contents($target, $value) !== false;
//     ↑ 这个 @
```

路径不存在时 `file_put_contents` 只是返回 `false`，而 `@` 把警告也吞掉了。
于是页面上既没有报错、也没有文件，只有一个「没有新文件」——
**看起来跟「payload 没构造对」一模一样。**

> 区分这两件事的办法很难靠猜：真正确定「链是通的、只是路径写错了」
> 是在命令行里单独 `unserialize` 一遍、打印 `getcwd()` 之后。
>
> 这类问题在真实排错里很常见，而且比语法错误难得多 ——
> **语法错误会告诉你哪里错了，静默失败不会。**

因为靶场的默认运行方式是 PHP 内置服务器，页面会直接把当前该填的路径
**算出来显示给你**（见 `html/lib/paths.php`）。
这不是给答案，是消掉一个和漏洞原理无关的环境噪音。

### 2.6 `__destruct` 的时机，以及它带来的一个陷阱

这一节是本档最值得记住的部分 —— 它涉及一个**很容易写错的地方**。

页面上那个「副作用检查」区块，逻辑是这样的：

```php
$beforeFiles = array_diff(scandir(TARGET_DIR), ['.', '..']);
$obj = @unserialize($data);
$afterFiles  = array_diff(scandir(TARGET_DIR), ['.', '..']);
$newFiles    = array_values(array_diff($afterFiles, $beforeFiles));
```

**如果照这样写，它永远会显示「没有新文件」** —— 哪怕 payload 完全正确。

原因：`__destruct()` 的默认触发时机是**脚本结束时**。
上面这段代码跑完之后，响应才开始发送，然后脚本结束 ——
`__destruct` 是在那一刻才把文件写出来的。

也就是说，`$afterFiles` 扫描的时候，文件**还没被创建**。

所以靶场代码里显式加了一行：

```php
$dump = print_r($obj, true);

unset($obj);   // ← 关键：让引用计数归零，__destruct 立即执行

$afterFiles = array_diff(scandir(TARGET_DIR), ['.', '..']);
```

`unset($obj)` 使对象引用计数归零，`__destruct()` 立刻被调用，文件当场落盘 ——
检查这才能看到「反序列化这个动作本身造成的副作用」。

> **这个细节本身就是一句很好的总结**：
> 反序列化的危害发生在「你以为一切都已经结束」之后。
>
> 而且这个坑是双向的：写检测逻辑的人如果不知道 `__destruct` 的时机，
> 会写出「永远显示没有副作用」的检查，然后误以为漏洞不存在。
> 反过来，防守方如果只在上面的业务逻辑里加校验，也不会拦住它 ——
> 因为触发点在业务逻辑之外。

### 2.7 顺带一提：覆盖同名文件看不出「新增」

副作用检查比对的是**新增**文件。所以如果连续两次都用 `pop.txt`，
第二次只是覆盖，目录里没有多出任何东西 —— 检查同样会显示「没有新文件」。

这也是 CI 里三条断言和 PoC 里三条请求**各自用不同文件名**的原因：

| 位置 | 文件名 |
|---|---|
| PoC ① low 档 | `pop_low.txt` |
| PoC ② medium 档 | `pop_medium.txt` |
| PoC ③ high 档 | `pop_high.txt` |

让每条载荷的副作用彼此独立，才能被单独观察到。
页面上也给了对应的提示，避免使用者把「覆盖」误判成「没打通」。

---

## 三、medium 档：类名黑名单与大小写绕过

### 3.1 防护措施

```php
$blacklist = ['FileStore', 'Cache', 'Logger'];
foreach ($blacklist as $bad) {
    if (strpos($data, $bad) !== false) {
        // 拦截
    }
}
$obj = @unserialize($data);   // 注意：这里依然没有任何类限制
```

思路是「把危险的类名拦掉」。但它有两个结构性问题。

### 3.2 绕过：类名不区分大小写，`strpos` 区分

PHP 的**类名是不区分大小写的**：

```php
class Cache {}
$c = new cache();   // 合法！和 Cache 是同一个类
```

而 `strpos()` 是**区分大小写**的字节比较。

于是把 payload 里的类名全改成小写：

```
O:5:"cache":3:{s:3:"key";s:7:"pop.txt";s:5:"value";s:20:"VULNLAB_POP_CHAIN_OK";s:5:"store";O:9:"filestore":1:{s:3:"dir";s:11:"../uploads/";}}
```

- 过滤器看字符串：找不到 `Cache` / `FileStore` → 放行
- 运行时解析类名：`cache` 和 `Cache` 是同一个类 → 正常实例化 → `__destruct` 照常触发

文件又写进去了。

### 3.3 这个绕过点其实和过滤器无关

值得单独说一下：**即使黑名单一个不漏，这个档位依然是可绕过的**。
因为黑名单列的是「危险的类」，而危险与否是**用法**决定的，不是类名决定的。

同一个 `Logger::__toString()`，在正常业务里只是拼个日志前缀；
但如果它被挂在 `Cache::$store` 上（`Logger` 并没有 `write` 方法，这里不成立，
但换成任何有 `__toString` 且能回调的类就成立），`__toString` 就成了链上的一环。

**一个类危险不危险，取决于它和谁串在一起 —— 而黑名单只能按名字列举。**

### 3.4 绕过手法远不止一种

除了大小写，PHP 序列化格式本身还有不少「等价但不同写法」：

| 写法 | 说明 |
|---|---|
| `O:5:` vs `O:+5:` | 长度前允许有 `+` 号，某些版本解析接受 |
| 属性个数的两种形态 | `O:5:"Cache":3:{...}` 与 `C:5:"Cache":...`（后者用于实现 `Serializable` 的类） |
| 引用语法 | `R:2;` / `r:2;` 可以引用已解析的对象，构造时能玩出别的花样 |

**只要过滤是按「字符串长什么样」判断，就总会有等价写法漏出去。**

---

## 四、high 档：`allowed_classes` 白名单

### 4.1 修复代码

```php
$allowed = ['SafeNote'];
$obj = @unserialize($data, ['allowed_classes' => $allowed]);
```

### 4.2 为什么这是唯一可靠的方向

黑名单问的是「**哪些类是危险的**」，白名单问的是「**这里真的需要哪些类**」。

这两个问题看起来只是措辞不同，实际差别是决定性的：

**黑名单会过期，而且没有任何机制提醒你。**
今天代码里只有 `Cache` / `FileStore` / `Logger` 三个类。黑名单列全了，看起来很安全。
下个月有人加了一个带 `__destruct` 的 `TemplateCache` ——
黑名单不会报错、不会有警告、Code Review 也未必有人注意到。
**它只是悄悄失效了。**

白名单反过来：不在这份名单上的类，无论将来加了多少个，一律拒绝。
新加的类要进入白名单，必须有人**明确地**把它写进去 —— 这一步是主动的。

### 4.3 被拒绝的类会发生什么

不在白名单里的类不会被「拒绝实例化」，而是被降级成 **`__PHP_Incomplete_Class`**：

```php
$obj = unserialize('O:9:"FileStore":1:{s:3:"dir";s:5:"/tmp/";}', ['allowed_classes' => ['SafeNote']]);
var_dump($obj);
// object(__PHP_Incomplete_Class)#1 (2) {
//   ["__PHP_Incomplete_Class_Name"] => string(9) "FileStore"
//   ["dir"] => string(5) "/tmp/"
// }
```

注意：**对象存在、属性也在，但方法不可用、魔术方法不触发。**

这对 POP 链是致命的 —— 链的每一环都依赖真实方法才能把控制流传递下去。
`Cache` 变成了空壳，`__destruct` 不会被调用，链在第一个节点就断了。

### 4.4 补充：如果根本不需要对象

```php
$obj = unserialize($data, ['allowed_classes' => false]);
```

如果业务只是解析数组或标量，`false` 比白名单更彻底 —— 一个类都不允许。

这也是靶场的 CI 里专门留了一条反向断言的原因：
**白名单里必须真的有那个需要的类**。
最省事的「修复」是 `false`，那确实谁也攻击不了，但业务也用不了了。
安全修复不该以牺牲功能为代价。

---

## 五、其他值得知道的手法

### 5.1 `__wakeup` 绕过（CVE-2016-7124）

PHP 7.0.10 之前，如果序列化串里声明的**属性个数大于实际个数**，
`__wakeup()` 会被跳过：

```
O:5:"Cache":4:{s:3:"key";s:7:"pop.txt";s:5:"value";s:1:"x";s:5:"store";N;}
              ↑ 声明 4 个，实际只给了 3 个
```

这是个**解析器层面的缺陷**（已修复），但它说明了一件事：
讲「用 `__wakeup` 做校验」是不够的 —— 校验本身可能被绕过。

### 5.2 `phar://` 反序列化

即使代码里完全没有 `unserialize()`，只要存在文件操作（`file_exists`、`filesize`、`getimagesize`……）
且路径可控，就能用 `phar://` 触发：

```php
file_exists('phar://uploaded.phar/any.txt');
// 读取 phar 元数据时，php 会自动反序列化 manifest 里的内容
```

**这是本靶场里文件包含场景的反向呼应**：LFI 的 `php://filter` 是用来**读**的，
而 `phar://` 是用来**触发**的。两者都说明「文件操作类函数」的输入边界比看起来宽得多。

### 5.3 从反序列化到 RCE

本靶场的终点是写文件，真实环境里通常是这两条路：

| 路径 | 做法 |
|---|---|
| 写文件 → 包含 | 写一个 `.php` 到可访问目录，再配合文件包含执行 |
| 原生 RCE 链 | 利用 `__call` / `__invoke` 套到框架内部的 gadget 上 |

第二条是真实漏洞里最常见的形态。Symfony、Laravel、Monolog、Guzzle 等
都因为自身存在大量魔术方法而成为 gadget 提供方 ——
这也是为什么 **「反序列化漏洞」往往不是应用自己写的类造成的**，
而是应用的依赖里恰好有能拼成链的类。

---

## 六、防御清单

| 层次 | 做法 | 说明 |
|---|---|---|
| ① **首选** | 不用序列化传数据 | 换成 JSON —— `json_decode` 只能得到数组/标量，构造不出对象 |
| ② 必须用时 | `allowed_classes` 白名单 | 只列出这里真正需要的类 |
| ③ 完全不需要对象 | `allowed_classes => false` | 最彻底 |
| ④ 传输层 | 对序列化串**做签名** | 攻击者无法伪造合法签名（但要防重放） |
| ⑤ 输入校验 | 校验序列化串的结构与长度 | 治标，容易被等价写法绕过 |
| ⑥ 依赖治理 | 定期审计依赖里的魔术方法 | 自己代码干净不代表链不存在 |

按有效性排序：**① > ②③ > ④ > ⑤**。

前两条是根治，后面的是缓解。
注意 ④ 只在「能保证密钥不泄露」时有效，且需要额外处理重放。

---

## 七、和本靶场其他场景的联系

这个场景是靶场里**第三个**「过滤器被绕过」的案例，放在一起看会更清楚：

| 场景 | 过滤器怎么想 | 解析器怎么做 | 缝隙在哪 |
|---|---|---|---|
| SQL 注入 | `str_replace` 扫一遍删 `union` | MySQL 逐字符解析关键字 | 删除动作把片段拼了回来 |
| 文件包含 | `str_replace` 删 `../` | 内核按路径语义解析 | 同上 |
| **反序列化** | `strpos` 按字符串找类名 | PHP 按**不区分大小写**找类 | 两者对大小写的态度不一致 |

三者的共同点一句话就能概括：

> **过滤器对输入的理解，和解析器对输入的理解，不是同一个理解。**

它们之间的差异，就是绕过点。

另一条联系在**修复方向**上：本靶场的 LFI high 档和这里的 high 档用的是同一个思路 ——
**白名单**。LFI 用白名单映射（只允许按名字取固定几个页面），
反序列化用 `allowed_classes`（只允许实例化固定几个类）。

这也是整个靶场反复出现的那条主线：
**黑名单在列举「敌人」，白名单在列举「自己人」。前者的完整性无法保证，后者可以。**

---

## 八、延伸阅读

- [PHP: unserialize - Manual](https://www.php.net/manual/en/function.unserialize.php) —— `allowed_classes` 参数
- [CVE-2016-7124](https://nvd.nist.gov/vuln/detail/CVE-2016-7124) —— `__wakeup` 绕过
- [OWASP: Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [phar:// 反序列化利用](https://github.com/ambionics/phar-deserialization) —— 无需 `unserialize()` 的触发路径
