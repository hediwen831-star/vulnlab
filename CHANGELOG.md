# 更新日志

本文件记录本项目的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 计划中

- PHP 反序列化（POP 链构造）
- 越权（水平 / 垂直 / IDOR）
- 文件包含（LFI / RFI）
- XXE
- JWT 伪造与弱密钥

---

## [0.1.0] - 2026-09-18

首个版本。**5 个漏洞场景，每个都凑齐四件套**（三档源码 + Writeup + 机读 PoC + 修复对照）。

### 新增

**漏洞场景**

| 场景 | low | medium 的绕过点 | high 的修复 |
|---|---|---|---|
| SQL 注入 | 数字型 UNION 注入 | 黑名单双写绕过 | 参数化查询 |
| XSS | 无转义输出 | `<img onerror>` 绕过标签黑名单 | `htmlspecialchars` 输出编码 |
| 文件上传 | 零校验 → getshell | 伪造 Content-Type | 白名单 + 内容检查 + 重命名 + 禁执行 |
| SSRF | 无限制打内网 + `file://` | `localhost` 绕过字符串黑名单 | 解析后校验 IP + 防 DNS 重绑定 |
| 命令注入 | 直接拼接 → RCE | `&` 绕过（黑名单漏掉 Windows 分隔符） | 白名单 + `escapeshellarg` |

**教学元素**

- SQL 场景把「服务端实际执行的 SQL」摊开给学习者看
- XSS 场景提供「服务端输出的 HTML」与「浏览器解析结果」**双视图对照** ——
  让「转义到底改变了什么」变得可见
- SSRF / 命令注入场景提供**逐层审计表格**，展示每一层校验看到了什么
- 每个 high 档都附带「修复要点总结」，覆盖实践中最常被追问的点

**基础设施**

- 模拟的「内网服务」（`html/internal/inner-service.php`），作为 SSRF 的攻击目标
- `start.sh` / `start.bat` 同时起两个服务（8080 靶场 + 8090 内网服务）
- Docker 部署（Dockerfile + docker-compose，两个服务）
- GitHub Actions CI：PHP 7.3 / 7.4 / 8.1 三版本矩阵

**CI 安全属性回归**（`tests/verify_lab.py`，**22 条断言**）

守的不是功能，是**安全属性**：

- 每个 low 档的漏洞场景**确实能打通**
- 每个 medium 档的绕过点**确实能绕过**
- 每个 high 档**打不动**，且**不牺牲功能**（反向保护，防止过度修复）
- 全站页面无 PHP 致命错误

### 修复

- **Docker 部署缺口**：compose 之前只起一个服务，而 SSRF 场景需要第二个
  「内网服务」—— 用 Docker 跑靶场时 SSRF 会打不通。
  现拆成两个服务，并新增 `VULNLAB_INTERNAL_BASE` 环境变量
  （容器内必须用服务名，因为容器里的 `127.0.0.1` 指向容器自己）
- **PHP 版本兼容**：`str_starts_with()`（PHP 8.0 引入）和箭头函数 `fn() =>`
  （PHP 7.4 引入）用在 PHP 7.3 上会 Fatal error，而页面只表现为「那一块内容消失」，
  `php -l` 完全正常。已改用兼容写法，并把 PHP 7.3 加进 CI 矩阵
- **命令输出为空**：Windows 上系统命令输出是 GBK 编码，
  直接丢给 `htmlspecialchars`（默认按 UTF-8）会触发「非法 UTF-8 序列」，
  而 PHP 在这种情况下**返回空字符串**而不是跳过非法字节 ——
  表现为「命令输出那一栏莫名其妙是空的」，不报错不告警。
  新增 `command_output_html()` 统一处理（先转码 + `ENT_SUBSTITUTE` 兜底）

### 记录在案的平台差异

这些是实测结论，都写进了对应的 Writeup：

- **SSRF**：`127.1` / `0x7f000001` / `2130706433` 等 IP 变形写法
  **Linux 有效、Windows 无效**（Linux 的 `inet_aton` 支持这些历史写法）
- **命令注入**：Windows cmd 不认 `;`、不支持换行作分隔符；`&` 才是 cmd 的主分隔符。
  而 `&` 在 Unix 上同样有效

> **payload 的有效性依赖目标环境** —— 这本身就是值得记录的知识点。

---

[Unreleased]: https://github.com/hediwen831-star/vulnlab/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hediwen831-star/vulnlab/releases/tag/v0.1.0
