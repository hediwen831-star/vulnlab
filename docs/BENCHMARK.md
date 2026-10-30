# 真值基准：把「误报」变成可计算的数

本文说明 `benchmark/` 目录的用途、真值怎么来、误报怎么归因、指标怎么算，
以及扫描器如何消费这套基准。

配套文件：

| 文件 | 作用 |
|---|---|
| `benchmark/manifest.yaml` | **真值清单**：121 个用例（13 场景 × 3 档 + 52 条负例变体 + 30 条诱饵页）的预期结论、证据、断言锚点、误报成因标签 |
| `benchmark/probes.yaml` | **探针**：同一份载荷打到不同档位，验证「该命中」与「不该命中」 |
| `tests/verify_benchmark.py` | 静态校验：清单 ↔ 源码 ↔ CI 断言 ↔ PoC 四者一致（不需要起靶场） |
| `tests/run_probes.py` | 动态校验：把探针真的打一遍，逐条比对预期 |

---

## 一、为什么需要真值清单

做误报量化，第一个卡住的问题不是算法，而是标准答案从哪来。

公开靶场几乎都只有「能被攻破」的场景。扫描器在那里报出漏洞，你无法判断
它是真的检测到了，还是恰好蒙对；更关键的是，**没有「本来就不该检出」的样本，
误报率的分母就是空的**。

VulnLab 的三档设计天然提供了这个分母：

| 档位 | 防护性质 | 预期结论 | 在评测中的角色 |
|---|---|---|---|
| `low` | 无防护 | 可被检出 | 正例（检出率分子） |
| `medium` | 有防护但可绕过 | 可被检出 | 正例，且考察绕过能力 |
| `high` | 已修复（功能完整） | **不可被检出** | **负例（误报率分子）** |

`high` 档不是「把功能删掉」换来的安全，页面照常可用、正常查询照常返回，
只是漏洞路径被真正堵死。这一点由 `tests/verify_lab.py` 里的
「修复档正常功能仍可用」断言守着。

所以：`high` 档上的任何一条漏洞报告都是误报，无需人工复核。
这把「误报率」从一个需要专家逐条判断的主观指标，变成了一个可自动计算的比例。

---

## 二、121 个用例：26 正例 + 95 负例

清单里的每一条都包含：

```yaml
- id: sqli-high
  scenario: sqli          # 场景
  tier: high              # 档位
  owasp: "A03:2021"       # 分类，便于按类聚合
  method: GET
  path: /sqli/high.php    # 扫描目标
  param: id
  expected: safe          # 真值：vulnerable | safe
  evidence: 参数化查询 + (int) 强转，注入载荷一律无效
  ci_checks:              # 该真值由哪些 CI 断言守护
    - "SQL · high 档注入被拒绝"
  poc: null               # 正例的机读 PoC
  cause_tags: [signature_collision]   # 若被扫错，最可能的成因
```

`ci_checks` 的作用是把清单钉在代码上：断言名不存在、被改名、被删除，
`verify_benchmark.py` 立刻报错。真值不会悄悄失效。

### 负例变体：每个 high 档 4 条绕过尝试

只有 13 条负例时，FPR 的一个样本值就是 7.7 个百分点，置信区间宽到没法下结论。
所以每个 high 档再补 4 条变体，13 × 5 = 65 条负例。四条变体固定对应四类手法：

| 变体 | 手法 | 例子 |
|---|---|---|
| 1 | 原始载荷复放 | 在 low 档成功的 UNION / `<script>` / `; id` 直接打到 high |
| 2 | 等价写法 | `localhost` 代 `127.0.0.1`、`1 OR 1=1`、管道符代替分号 |
| 3 | 编码或语法变形 | 反引号、换行、`php://filter`、双扩展名、`alg=none` |
| 4 | 边界值或链式 | 负值、数组参数、十进制 IP、`file://`、外部 DTD |

分类口径对齐 OWASP WSTG 与 PayloadsAllTheThings，每条在 `bypass` 字段里写明
`technique` / `basis` / `reference`。变体自带 `request` 与 `expect_blocked`：

```yaml
- id: sqli-high-bypass-1
  variant: 1
  request:
    query: {id: "-1 UNION SELECT 1,username,secret,role FROM users"}
  expect_blocked:
    forbid: ["VULNLAB{", "SQLSTATE"]   # 结果里不能出现的东西
    require: "订单不存在"                # 必须出现的拒绝文案（可选）
    region: "渲染结果"                   # 只看结果区，避免把回填当执行（可选）
```

`region` 这一项是必须的：页面会把输入原样回填进表单，只在整页里找 marker
会把「回显」当成「执行」，这正是低质量扫描器犯的错 —— 校验脚本自己不能犯。

### 诱饵页：另一类负例

变体回答的是「修复后的实现能不能被打穿」；诱饵页回答的是「页面正常回显时，
判据会不会把编码后的输出当成注入」。两者是不同的误报成因，必须分开覆盖。

10 个诱饵页都是安全实现：回显前 `htmlspecialchars`、JSON 原样返回、
参数只用于白名单查表、上传接口直接 405。每页 3 条请求（HTML 标签、SQL 片段、路径片段），
共 30 条负例，全部带 `expect_blocked`，由重放脚本守着。

这一层是上一版基准缺的：只有「修复页」时，naive 的误报只有 8 条，
统计上不足以支撑结论；补了诱饵页之后误报样本到 29 条，McNemar 才过得了 0.05。

**正例保持 26 条不动。** 扩负例是为了压窄 FPR 的区间；TPR 的 26 个样本
给出 95% 区间 87%–100%，对「方法可行性」的论证已经够用，再加正例边际收益低。

---

## 三、误报成因分解与归因规则

课题的核心主张是「误报可以拆解」。分解口径：

| 成因 | 定义 | 在 VulnLab 里的对应样本 |
|---|---|---|
| `wildcard_dns` | 泛解析：不存在的主机名也能解析，被当作存活资产 | 资产层，见 attack-surface 侧用例 |
| `identity_dependency` | 身份依赖：无凭据 / 凭据不足时结论不可靠 | `idor*`、`jwt`、`csrf` 的他人资源访问 |
| `dynamic_content` | 动态内容：两次响应天然不同，响应比对判据失效 | `jwt-medium`（需离线爆破后重签） |
| `stateful_side_effect` | 有状态副作用：首次与再次执行结果不同 | `csrf-high`（token 轮换）、`unserialize-*`（覆盖写文件）、`upload-*` |
| `signature_collision` | 特征自污染：检测特征被检测行为本身制造出来 | `sqli-high`（提交值回填输入框）、`xss-high`（转义后文本仍含载荷）、`lfi-high` |
| `none` | 非上述成因（纯判定逻辑错误） | — |

归因优先级（一条误报可能同时命中多个成因时，按此顺序取第一个）：

```
wildcard_dns > identity_dependency > stateful_side_effect > signature_collision > dynamic_content > none
```

理由：越靠前的成因越「结构性」，它决定了这条误报是否需要更换检测范式，
而不只是调整判据。例如一条误报若源于泛解析，那么改 matcher 是治不好的；
若只是特征自污染，收紧判据即可。

---

## 四、指标定义

对某个被测工具 $T$、某个用例集合 $C$：

| 符号 | 含义 |
|---|---|
| $V$ | 预期为 `vulnerable` 的用例集合（本基准 26 条） |
| $S$ | 预期为 `safe` 的用例集合（本基准 65 条） |
| $TP$ | $V$ 中被报出漏洞的用例数 |
| $FN$ | $V$ 中未被报出的用例数 |
| $FP$ | $S$ 中被报出漏洞的用例数 |
| $TN$ | $S$ 中未被报出的用例数 |

$$
\text{检出率 } TPR = \frac{|TP|}{|V|}, \qquad
\text{误报率 } FPR = \frac{|FP|}{|S|}
$$

分项误报率（按成因拆解，这是「总误报率」之外的第二个维度）：

$$
FPR_c = \frac{\bigl|\{\, x \in FP \;|\; \text{dominant\_cause}(x) = c \,\}\bigr|}{|S_c|}
$$

其中 $S_c$ 是负例中成因标签含 $c$ 的用例数。

**FPR 的分母固定为全部 95 条负例（65 条场景负例 + 30 条诱饵页）。** 这是扫描器基准的通行口径：
没有报出来就是没有误报；没去尝试是覆盖问题，不是误报。
为了不让人误读，报告里会单独列「尝试用例数」——它只用于展示，
不参与 FPR 计算。否则「少测少错」的工具反而会拿到更漂亮的误报率。这样不同工具、不同场景之间
才谈得上横向比较，「误报率 20%」若不拆开，既不知道问题出在哪一层，
也不知道该换范式还是改判据。

降噪的代价（只报降噪幅度而不报代价，是可复现性上的常见缺陷）：

$$
\Delta FPR = FPR_{\text{原始}} - FPR_{\text{降噪后}}, \qquad
\Delta TPR = TPR_{\text{原始}} - TPR_{\text{降噪后}}, \qquad
\text{cost} = \frac{\text{LLM 调用次数}}{|C|}
$$

约束：$\Delta TPR$ 不得为正（降噪不该提升检出率，否则说明原流程有遗漏），
且需报告 $\Delta TPR > 0$ 时的具体用例，过杀就藏在这里。

---

### 报告口径与置信区间

样本量决定结论强度，所以每份报告都要能回答「这个数有多稳」。基准的负例
从 13 扩到 65 就是为了这个：0/13 的 95% 置信区间上限约 23%，
0/95 约 3.9%（Wilson 区间）。论文里的任何比率都应带区间，而不是只写百分比。

## 五、探针：控制变量的最小实验

`benchmark/probes.yaml` 里每条探针只做一件事：把已验证的载荷打到另一档上。

```yaml
- id: xss-high-negative
  case: xss-high
  expect: no_match
  from: {poc: pocs/vulnlab-xss-reflected.yaml, request: 0}
```

`from` 表示复用该 PoC 的请求，运行时只替换路径里的档位段，
载荷、请求头、判据全部不变。唯一变量是防护档位，这是控制变量。

判定：

- `expect: match` 而实测未命中 → 正例漏检，计入 $FN$
- `expect: no_match` 而实测命中 → 负例误报，计入 $FP$

运行（需要靶场已启动）：

```bash
python tests/run_probes.py --url http://127.0.0.1:8080
python tests/run_probes.py --only sqli --json
```

---

## 六、一个实测案例：特征自污染

第一次跑探针时，`sqli-high-negative` 报了「实测 match」。排查结果：

```
high.php 的响应里，提交值被原样回填到输入框：
<input type="text" name="id" value="-1 UNION SELECT 1,'VULNLAB_POC_MARKER',3,4">
```

参数化查询确实生效了（数据库没有执行注入），但载荷文本出现在了响应里。
只做「响应含标记串」判定的扫描器，会在这个已修复页面上报出 SQL 注入。

这不是靶场的缺陷，而是真实世界最典型的一类误报：
检测特征被检测行为本身制造出来。修法不是放弃检测，而是把判据锚定到
「结果渲染区」这种只有真正注入成功才会出现的结构上：

```yaml
matchers:
  - type: regex
    regex: ['<td class="mono">VULNLAB_POC_MARKER</td>']
```

这条经验直接支撑 `signature_collision` 这个成因类别，
它也是本基准里最容易复现、最容易被忽视的一类。

---

## 七、当前状态与覆盖缺口

| 项目 | 数量 |
|---|---|
| 用例 | 121（正例 26 / 负例 95） |
| 有 CI 断言守护 | 121（89 条基础断言 + 82 条负例重放：52 变体 + 30 诱饵页） |
| 有机读 PoC | 26 |
| 有探针 | 16 |

三个档位、121 个用例的真值全部被 CI 断言守着；其中 16 个用例另有探针
（13 条基础负例 + 3 条原 PoC 未覆盖的正例）。52 条负例变体与 30 条诱饵页由
`tests/verify_negatives.py` 逐条重放校验（82 条）。

历史缺口（已补齐，留档说明补法）：

| 用例 | 原缺口 | 补法 |
|---|---|---|
| `upload-medium` | 无 CI 断言、无 PoC | 断言「伪造 Content-Type 后 .php 被接受」；探针自带请求 |
| `ssrf-low` | 无 CI 断言 | 断言「能读到内网服务内容」，依赖 8090 端口（CI 已起） |
| `ssrf-medium` | 无 CI 断言、无 PoC | 两条断言：裸 `127.0.0.1` 被拦 + `localhost` 绕过；探针自带请求 |

补齐后基础断言 86 → 89 条（负例变体不计入这 89 条）。

---

## 八、评测框架（`benchmark/harness/`）

```
benchmark/harness/
├── evaluate.py          # 入口：跑一个被测对象 → 指标 + JSON/Markdown 明细
├── loader.py            # 清单/探针读取、请求构造、路径归一
├── matchers.py          # matcher 求值（唯一实现，探针脚本共用）
└── adapters/
    ├── probe.py         # 判据上限：用例自带的判据（理想检测器）
    ├── asp.py           # attack-surface，走 `asp poc run --json`
    ├── naive.py         # 反射式基线：响应含载荷标记即报
    ├── nuclei.py        # 外部引擎：调用 Nuclei，读 JSONL（模板见 benchmark/nuclei/）
    └── json_import.py   # 任意第三方工具的 JSON / JSONL 导出
```

适配器协议只有一条：返回

```python
{"tool": "...", "reachable": True, "findings": [
    {"url": "...", "rule": "...", "severity": "...", "source": "..."}
]}
```

新增被测工具时只写适配器，不需要碰指标计算。

```bash
# 判据上限（验证评测链路：应为 TPR 100% / FPR 0%）
python benchmark/harness/evaluate.py --scanner probe --url http://127.0.0.1:8080

# 自研引擎
python benchmark/harness/evaluate.py --scanner nuclei --url http://127.0.0.1:8080
python benchmark/harness/evaluate.py --scanner asp --url http://127.0.0.1:8080 \
    --asp-repo ../attack-surface --asp-python <装了依赖的解释器>

# 第三方工具（Nuclei `-jsonl` / Xray / ZAP 导出均可）
python benchmark/harness/evaluate.py --scanner json --url http://127.0.0.1:8080 \
    --findings nuclei.jsonl --label nuclei
```

每次评测会在 `benchmark/results/` 留三样东西：终端表格、`.json`（含逐条命中与归属，
可复算）、`.md`（可直接粘进报告的表格）。

第一批评测数据与结论见 [`benchmark/results/M2-matrix.md`](../benchmark/results/M2-matrix.md)；
降噪实验（复核前后 TPR/FPR 变化）见 [`benchmark/results/M4-denoise.md`](../benchmark/results/M4-denoise.md)。

降噪阶段的入口是 `benchmark/harness/denoise.py`：

```bash
python benchmark/harness/denoise.py --scanner naive --url http://127.0.0.1:8080 \
    --asp-repo ../attack-surface --provider openai --rounds 3
```

它重放每条命中的原请求取证据，交给复核方判断，再算一次指标。
URL、规则名、页面标题里的档位与「已修复」字样会先抹掉，避免把答案泄漏给模型。

### 归属规则

同一个 high 页现在挂着 5 条用例（基础 + 4 条变体），只按路径会串味。
归属分三级：

1. 规则名里带 case id（`naive-marker:sqli-high-bypass-1`）→ 直接采纳；
2. 查询参数与某条变体的 `request.query` 完全一致 → 归属该变体；
3. 其余按路径归到**基础用例**（变体的误报不单独计，避免同一次误报重复计数）。

路径不在清单里时，若该命中所用 PoC 只对应唯一用例，则归属到该用例
（例如 upload 的第二步会访问 `/uploads/xxx`，结论属于 `upload-low`）。
三条都不成立时计入 `unattributed`，不进 TP/FP，宁可少算，不猜。

