# M2 第一批评测数据（2026-10-23）

## 实验设置

| 项 | 值 |
|---|---|
| 基准 | VulnLab v0.2.0 + 真值清单（39 用例：正例 26 / 负例 13） |
| 靶场 | `php -S 127.0.0.1:8080`（主站）+ `:8090`（模拟内网服务） |
| 被测对象 | `probe`（判据上限）、`asp`（attack-surface 自研引擎）、`naive`（只查载荷反射的基线） |
| 判定 | 按 URL 路径映射到用例；映射不上的命中单独统计，不进指标 |
| 原始数据 | 同目录 `*-20261023-*.json`（含每条命中的规则名与用例归属） |

## 主表

| 被测对象 | TPR（检出率） | FPR（误报率） | 说明 |
|---|---:|---:|---|
| `probe` | **100.0%**（26/26） | **0.0%**（0/13） | 判据与真值一致时的上界，用于验证评测链路本身 |
| `asp` | 92.3%（24/26） | 0.0%（0/13） | 自研引擎，PoC 全覆盖 + 负向对照 |
| `naive` | 30.8%（8/26） | **30.8%**（4/13） | 只查「响应里有没有载荷标记」 |

## 分项误报率

| 成因 | 负例总数 | probe | asp | naive |
|---|---:|---:|---:|---:|
| 泛解析 `wildcard_dns` | 0 | — | — | — |
| 身份依赖 `identity_dependency` | 3 | 0.0% | 0.0% | 0.0% |
| 有状态副作用 `stateful_side_effect` | 3 | 0.0% | 0.0% | 33.3% |
| 特征自污染 `signature_collision` | 7 | 0.0% | 0.0% | **42.9%** |
| 动态内容 `dynamic_content` | 0 | — | — | — |

（`wildcard_dns` / `dynamic_content` 属资产层与响应稳定性问题，应用层基准里暂无对应负例，
这两项要在 attack-surface 的资产发现评测里测，见 M3。）

## 三条可直接写进论文的结论

**1. 判据正确时误报率可以做到 0，且不需要模型。**
`probe` 与 `asp` 都在 13 条真负例上零误报，区别只在检出率。
这说明「误报主要由判据结构决定，而不是目标的复杂度决定」——
LLM 复核应当只处理判据无法确定的那部分，而不是全量兜底。

**2. 检出率的上限是 PoC 覆盖率，不是引擎能力。**
`asp` 漏掉的两条（`upload-medium`、`ssrf-medium`）恰好是唯一没有对应 PoC 文件的两个档位：
引擎只能执行 `pocs/` 里已有的检测逻辑。这给出一条可量化的工程结论：

> 扫描器的检出率 $\leq$ 其 PoC 库对该基准的覆盖率。

反过来说，`probe` 能 100% 是因为每个用例都有判据 —— 补齐 PoC 即可把 `asp` 拉到同一条线。

**3. 反射式判据同时造成误报与漏报。**
`naive` 的 4 条误报全部落在「页面会回显载荷」的用例（`sqli-high`、`cmdi-high`、`xss-high`、
`unserialize-high`），而 18 条漏检里有 12 条是「证据不在载荷里」的场景
（LFI 读文件内容、XXE 读实体、IDOR 读他人数据）。
即：**判据锚在输入上，既会把修复判成漏洞，也会把漏洞判成干净。**
这不是调参能解决的，必须把判据锚到「只有成功才出现的结构」。

## 方法论记录：先验归因 vs 实测归因

清单里的 `cause_tags` 是**先验判断**，本轮实测修正了一处：

- `unserialize-high` 先验标为 `stateful_side_effect`（副作用覆盖写文件、判据不幂等），
  但 `naive` 在它上面误报的真实原因是页面回显了序列化串 —— 属 `signature_collision`。

所以分项误报率必须基于**实测归属**（本轮按 URL + 规则名 + 响应证据反推），
先验标签只作为待验证的假设。这条经验会写进归因规则：
**先验标签用于设计实验，不用于直接出数。**

## 已知局限

| 局限 | 说明 | 计划 |
|---|---|---|
| 外部商业/开源扫描器未接入 | 本机没有 Xray / Nuclei / ZAP 的可执行文件 | 已提供 `json` 适配器，任意工具导出 JSON/JSONL 即可评测；装上二进制后补跑 |
| 应用层只有路径级用例 | 泛解析、动态内容两类成因在应用层无对应负例 | M3 在 attack-surface 资产发现链路上补资产层用例 |
| 单轮测量 | 未做重复实验与置信区间 | M4 增加 3 轮重复，报告均值与波动 |

## 复现

```bash
# 1. 起靶场（两个端口都要）
php -S 127.0.0.1:8080 -t html &
php -S 127.0.0.1:8090 -t html &

# 2. 三个被测对象
python benchmark/harness/evaluate.py --scanner probe --url http://127.0.0.1:8080
python benchmark/harness/evaluate.py --scanner naive --url http://127.0.0.1:8080
python benchmark/harness/evaluate.py --scanner asp   --url http://127.0.0.1:8080 \
    --asp-repo ../attack-surface --asp-python <装了依赖的解释器>

# 3. 第三方工具（导出 JSON 后）
python benchmark/harness/evaluate.py --scanner json --url http://127.0.0.1:8080 \
    --findings path/to/nuclei.jsonl --label nuclei
```
