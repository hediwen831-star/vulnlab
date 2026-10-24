# M4：降噪效果量化

## 实验设置

| 项 | 值 |
|---|---|
| 基准 | VulnLab 39 用例（26 正例 / 13 负例） |
| 靶场 | `php -S 127.0.0.1:8080` + `:8090` |
| 被测对象 | `naive`（只查载荷反射，误报多）、`asp`（自研引擎，无误报） |
| 复核方 | `heuristic`（规则降级）、`openai`（DeepSeek `deepseek-chat`，温度 0） |
| 轮次 | 3 轮（启发式只跑了 1 轮，剔除数恒为 0） |
| 证据构造 | 重放命中的原请求（GET/POST 原样），截取载荷标记出现位置前后各 200 字符，最多两处 |
| 档位脱敏 | URL、规则名、页面标题里的 low/medium/high 与「已修复」字样一律抹掉 |

## 结果

| 扫描器 | 复核 | TPR 前 → 后 | FPR 前 → 后 | 剔除数/轮 | 实际调用 |
|---|---|---|---:|---:|---:|
| naive | heuristic | 30.8% → 30.8% | 30.8% → 30.8% | 0 | 12 |
| naive | DeepSeek | 30.8% → 30.8% | **30.8% → 15.4%** | 2 | 36 |
| asp | DeepSeek | **100% → 92.3%** | 0% → 0% | 3 | 32 |

三轮之间结论稳定。`asp` 那组第 2、3 轮有 29/30 次判定命中缓存（同证据同结论），
所以实际调用 32 次而不是 93 次。

## 三条结论

**1. 启发式在这类误报上完全无效。**
它只认「404 / 错误页 / 默认中间件页面」这些信号，而 VulnLab 的误报页面全是 200
的正常页面，只是载荷被回填进了输入框。剔除数 0。这条差异本身说明：
反射型误报需要看「标记出现在哪」，不是看「页面像不像错误页」。

**2. LLM 能摘掉反射型误报，但要靠证据构造。**
第一版证据只截「标记第一次出现」的位置，而那恰好是 `<input value="...">`，
于是模型把 `sqli-low`（真漏洞）和 `sqli-high`（误报）都判成误报，
TPR 从 30.8% 掉到 7.7%。改成「多出现位置 + 按结果区特征打分排序」之后：
同一份载荷，`low` 档读到结果表格里的标记，判真阳性；`high` 档只有输入回填，判误报。
最终 2 条误报被剔除，0 条真漏洞被误杀。

**3. 在没有误报可降的时候，LLM 只会造成损失。**
`asp` 本身 FPR 为 0，复核却砍掉了 3 条真命中（`unserialize-low`、`ssti-low` 两条），
TPR 从 100% 掉到 92.3%，误报率没有任何改善。这是净负收益。

对应的工程结论：复核结论只能作为标注，不能直接删除命中。
`asp/llm.py` 原本就是这么设计的（只写 `is_false_positive` + `reason`，
原始记录不动），这次实验给出了支持它的数据。

## 剩余误报

`naive` 的 4 条误报里还剩 2 条没被摘掉：

- `xss-high`：载荷被 HTML 转义后仍然出现在响应里，模型看到的是转义文本，
  没有「是否可执行」的判断依据。
- `unserialize-high`：页面回显了提交的序列化串，和「反序列化执行成功」在文本上难以区分。

这两类要在判据层面处理（转义检测、副作用幂等检查），LLM 拿纯文本判断不了。

## 已知局限

| 局限 | 说明 |
|---|---|
| 单模型单温度 | 只测了 DeepSeek 一个模型，temperature=0，没有跨模型对比 |
| 样本量小 | 每轮最多 31 条命中，统计意义有限，结论只对本基准成立 |
| 证据是重放快照 | 有状态页面（CSRF token、上传文件名）跨轮变化，缓存无法完全复用 |
| 成本只统计调用 | 按 call 数 + 字符数报告，没有换算成金额（价格随厂商调整） |

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

原始数据：`denoise-naive-heuristic-*.json`、`denoise-naive-m4b-openai-*.json`、
`denoise-asp-m4-openai-*.json`。
