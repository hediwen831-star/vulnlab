# M4：降噪效果量化（v2，2026-10-24，基准 91 例）

## 实验设置

| 项 | 值 |
|---|---|
| 基准 | VulnLab 91 用例（26 正例 / 65 负例） |
| 靶场 | `php -S 127.0.0.1:8080` + `:8090` |
| 被测对象 | `naive`（误报 8 条）、`asp`（0 误报） |
| 复核方 | `heuristic`（规则降级）、`openai`（DeepSeek `deepseek-chat`，温度 0） |
| 轮次 | 3 轮（启发式只跑 1 轮，剔除数恒为 0） |
| 证据构造 | 重放命中的原请求，按结果区特征截取标记所在片段，最多两处 |
| 档位脱敏 | URL、规则名、页面标题里的 low/medium/high 与「已修复」一律抹掉 |

## 结果

| 扫描器 | 复核 | TPR 前 → 后 | FPR 前 → 后 | 剔除/轮 | 实际调用 |
|---|---|---|---:|---:|---:|
| naive | heuristic | 30.8% → 30.8% | 12.3% → 12.3% | 0 | 16 |
| naive | DeepSeek | 30.8% → 30.8% | **12.3% → 4.6%** | 5 | 20 |
| asp | DeepSeek | **100% → 92.3%** | 0% → 0% | 3 | 34 |

三轮之间结论稳定，每轮剔除的用例完全相同。判定按「证据 + URL」缓存，
第 2、3 轮直接复用，所以实际调用远少于「命中数 × 轮次」。

## 四条结论

**1. 启发式在这类误报上依然完全无效。**
它只认「404 / 错误页 / 默认中间件页面」这些信号，而 VulnLab 的误报页面全是
正常的 200 页面，只是载荷被回填进了输入框。剔除数 0。

**2. LLM 摘掉了 5 条误报，且没有误杀。**
naive 的 8 条误报中，`sqli-high`、`cmdi-high`、`cmdi-high-bypass-3/4`、
`ssti-high-bypass-2` 被判为误报，TPR 保持 30.8% 不变。
剩下 3 条（`xss-high`、`xss-high-bypass-2`、`unserialize-high`）没摘掉：
前两条是「载荷被 HTML 转义后仍在页面里」，后一条是序列化串回显 ——
纯文本判断不出「转义后不可执行」和「序列化不等于反序列化」，需要判据层面处理。

**3. 在没有误报可降的时候，LLM 只会造成损失。**
`asp` 本身 FPR 为 0，复核却砍掉 3 条真命中（`unserialize-low`、`ssti-low` 两条），
TPR 从 100% 掉到 92.3%，误报率没有任何改善。这是净负收益。

对应的工程结论：复核结论只能作为标注，不能直接删除命中。
`asp/llm.py` 原本就是这么设计的（只写 `is_false_positive` + `reason`，
原始记录不动），这次实验给出了支持它的数据。

**4. 效果的统计强度仍然有限。**
naive 的 FPR 从 12.3% 降到 4.6%，是 8 条误报减少到 3 条。配对检验（McNemar 精确检验）
双侧 p = 0.0625，刚好没到 0.05。也就是说：方向明确、机理清楚，但**样本量还不够**
把「降噪有效」写成统计显著。这一点必须写进论文的局限，不能含糊过去。

## 与旧基准（n=13）的对照

| 实验 | n=13 | n=65 |
|---|---|---|
| naive + 启发式 | 30.8% → 30.8% | 12.3% → 12.3% |
| naive + DeepSeek | 30.8% → 30.8%（剔除 2） | 30.8% → 30.8%（剔除 5） |
| asp + DeepSeek | 100% → 92.3%（误杀 3） | 100% → 92.3%（误杀 3） |

扩负例之后，naive 的误报从 4 条涨到 8 条（变体让「回显即漏洞」的缺陷暴露更多），
LLM 摘掉的绝对数量也从 2 涨到 5，比例仍在一半左右。结论方向没变，但证据厚了一倍。

旧数据与旧报告在 `benchmark/results/archive/n13/`。

## 已知局限

| 局限 | 说明 |
|---|---|
| 单模型单温度 | 只测了 DeepSeek 一个模型，temperature=0，没有跨模型对比 |
| 样本量 | 8 条误报，McNemar 不显著；要显著需要把误报样本提到 15 条以上 |
| 证据是重放快照 | 有状态页面（CSRF token、上传文件名）跨轮变化，缓存无法完全复用 |
| 成本只统计调用 | 按 call 数 + 字符数报告，没有换算成金额 |

## 复现

```bash
# 起靶场
php -S 127.0.0.1:8080 -t html &
php -S 127.0.0.1:8090 -t html &

# 规则降级
python benchmark/harness/denoise.py --scanner naive --url http://127.0.0.1:8080 \
    --asp-repo ../attack-surface --provider heuristic --rounds 3

# DeepSeek 复核
export ASP_LLM_API_KEY=...
export ASP_LLM_BASE_URL=https://api.deepseek.com/v1
export ASP_LLM_MODEL=deepseek-chat
python benchmark/harness/denoise.py --scanner naive --url http://127.0.0.1:8080 \
    --asp-repo ../attack-surface --provider openai --rounds 3
```

原始数据：`denoise-naive-heuristic-*.json`、`denoise-naive-openai-*.json`、
`denoise-asp-openai-*.json`。
