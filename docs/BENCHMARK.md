# 真值基准：把「误报」变成可计算的数

本文说明 `benchmark/` 目录的用途、真值怎么来、误报怎么归因、指标怎么算，
以及扫描器如何消费这套基准。

配套文件：

| 文件 | 作用 |
|---|---|
| `benchmark/manifest.yaml` | **真值清单**：39 个用例（13 场景 × 3 档）的预期结论、证据、断言锚点、误报成因标签 |
| `benchmark/probes.yaml` | **探针**：同一份载荷打到不同档位，验证「该命中」与「不该命中」 |
| `tests/verify_benchmark.py` | 静态校验：清单 ↔ 源码 ↔ CI 断言 ↔ PoC 四者一致（不需要起靶场） |
| `tests/run_probes.py` | 动态校验：把探针真的打一遍，逐条比对预期 |

---

## 一、为什么需要真值清单

做误报量化，第一个卡住的问题不是算法，而是**标准答案从哪来**。

公开靶场几乎都只有「能被攻破」的场景。扫描器在那里报出漏洞，你无法判断
它是真的检测到了，还是恰好蒙对；更关键的是，**没有「本来就不该检出」的样本，
误报率的分母就是空的**。

VulnLab 的三档设计天然提供了这个分母：

| 档位 | 防护性质 | 预期结论 | 在评测中的角色 |
|---|---|---|---|
| `low` | 无防护 | 可被检出 | 正例（检出率分子） |
| `medium` | 有防护但可绕过 | 可被检出 | 正例，且考察绕过能力 |
| `high` | 已修复（功能完整） | **不可被检出** | **负例（误报率分子）** |

`high` 档不是「把功能删掉」换来的安全 —— 页面照常可用、正常查询照常返回，
只是漏洞路径被真正堵死。这一点由 `tests/verify_lab.py` 里的
「修复档正常功能仍可用」断言守着。

所以：**`high` 档上的任何一条漏洞报告都是误报，无需人工复核。**
这把「误报率」从一个需要专家逐条判断的主观指标，变成了一个可自动计算的比例。

---

## 二、39 个用例

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

`ci_checks` 的作用是把清单**钉在代码上**：断言名不存在、被改名、被删除，
`verify_benchmark.py` 立刻报错。真值不会悄悄失效。

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

**归因优先级**（一条误报可能同时命中多个成因时，按此顺序取第一个）：

```
wildcard_dns > identity_dependency > stateful_side_effect > signature_collision > dynamic_content > none
```

理由：越靠前的成因越「结构性」——它决定了这条误报是否需要更换检测范式，
而不只是调整判据。例如一条误报若源于泛解析，那么改 matcher 是治不好的；
若只是特征自污染，收紧判据即可。

---

## 四、指标定义

对某个被测工具 $T$、某个用例集合 $C$：

| 符号 | 含义 |
|---|---|
| $V$ | 预期为 `vulnerable` 的用例集合（本基准 26 条） |
| $S$ | 预期为 `safe` 的用例集合（本基准 13 条） |
| $TP$ | $V$ 中被报出漏洞的用例数 |
| $FN$ | $V$ 中未被报出的用例数 |
| $FP$ | $S$ 中被报出漏洞的用例数 |
| $TN$ | $S$ 中未被报出的用例数 |

$$
\text{检出率 } TPR = \frac{|TP|}{|V|}, \qquad
\text{误报率 } FPR = \frac{|FP|}{|S|}
$$

**分项误报率**（按成因拆解，这是「总误报率」之外的第二个维度）：

$$
FPR_c = \frac{\bigl|\{\, x \in FP \;|\; \text{dominant\_cause}(x) = c \,\}\bigr|}{|S_c|}
$$

其中 $S_c$ 是负例中成因标签含 $c$ 的用例数。这样不同工具、不同场景之间
才谈得上横向比较 —— 「误报率 20%」若不拆开，既不知道问题出在哪一层，
也不知道该换范式还是改判据。

**降噪的代价**（只报降噪幅度而不报代价，是可复现性上的常见缺陷）：

$$
\Delta FPR = FPR_{\text{原始}} - FPR_{\text{降噪后}}, \qquad
\Delta TPR = TPR_{\text{原始}} - TPR_{\text{降噪后}}, \qquad
\text{cost} = \frac{\text{LLM 调用次数}}{|C|}
$$

约束：$\Delta TPR$ 不得为正（降噪不该提升检出率，否则说明原流程有遗漏），
且需报告 $\Delta TPR > 0$ 时的具体用例 —— 过杀就藏在这里。

---

## 五、探针：控制变量的最小实验

`benchmark/probes.yaml` 里每条探针只做一件事：**把已验证的载荷打到另一档上**。

```yaml
- id: xss-high-negative
  case: xss-high
  expect: no_match
  from: {poc: pocs/vulnlab-xss-reflected.yaml, request: 0}
```

`from` 表示复用该 PoC 的请求，运行时只替换路径里的档位段，
**载荷、请求头、判据全部不变**。唯一变量是防护档位 —— 这是控制变量。

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

参数化查询确实生效了（数据库没有执行注入），但**载荷文本出现在了响应里**。
只做「响应含标记串」判定的扫描器，会在这个已修复页面上报出 SQL 注入。

这不是靶场的缺陷，而是真实世界最典型的一类误报：
**检测特征被检测行为本身制造出来**。修法不是放弃检测，而是把判据锚定到
「结果渲染区」这种只有真正注入成功才会出现的结构上：

```yaml
matchers:
  - type: regex
    regex: ['<td class="mono">VULNLAB_POC_MARKER</td>']
```

这条经验直接支撑 `signature_collision` 这个成因类别 ——
它也是本基准里最容易复现、最容易被忽视的一类。

---

## 七、当前状态与覆盖缺口

| 项目 | 数量 |
|---|---|
| 用例 | 39（正例 26 / 负例 13） |
| 有 CI 断言守护 | 39 |
| 有机读 PoC | 24 |
| 有探针 | 16 |

三个档位、39 个用例的真值全部被 CI 断言守着；其中 16 个用例另有探针
（13 条负例 + 3 条原 PoC 未覆盖的正例）。

历史缺口（已补齐，留档说明补法）：

| 用例 | 原缺口 | 补法 |
|---|---|---|
| `upload-medium` | 无 CI 断言、无 PoC | 断言「伪造 Content-Type 后 .php 被接受」；探针自带请求 |
| `ssrf-low` | 无 CI 断言 | 断言「能读到内网服务内容」，依赖 8090 端口（CI 已起） |
| `ssrf-medium` | 无 CI 断言、无 PoC | 两条断言：裸 `127.0.0.1` 被拦 + `localhost` 绕过；探针自带请求 |

补齐后 CI 断言 86 → 89 条。

---

## 八、如何被外部消费

评测脚本（M2 阶段实现，规划在 attack-surface 侧）读取顺序：

1. `benchmark/manifest.yaml` 得到全部用例与真值；
2. 对 `vulnerable` 用例，跑对应 `poc`（正例）；
3. 对 `safe` 用例，跑对应探针（`probes.yaml`），命中即误报；
4. 按 `cause_tags` 聚合出 $FPR_c$。

清单是纯数据，不绑定任何特定扫描器 —— 换被测工具时不需要改基准。
