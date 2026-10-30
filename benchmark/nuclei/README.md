# Nuclei 接入：24 个模板与被测边界

## 这是什么

`templates/` 下 24 个 Nuclei 模板：12 个 low 档 + 12 个 medium 档。
它们是**我们自己写的**，不是官方模板库的一部分 —— 官方模板针对真实产品
（WordPress、Jenkins、Spring 等），不覆盖这个靶场的路径。直接跑官方模板
只会得到 0 命中，那不叫「Nuclei 的检出率」，叫「模板没写」。

真正被比较的是：**同一个可表达的检测任务，用不同引擎实现，误报与漏报如何。**

## 实测结果（2026-10-30，基准 121 例）

| 工具 | TPR | FPR | 命中 | 未归属 |
|---|---:|---:|---:|---:|
| nuclei（24 模板） | 92.3%（24/26） | 0.0%（0/95） | 24 | 0 |

- 24 条命中全部落在 low/medium 正例上，归属正确；
- 漏的两条是 `ssti-low`、`ssti-medium`，原因见下；
- 95 条负例零误报，但**这个 0 的说服力有限**：模板只打 low/medium 路径，
  既不会碰 high 档，也不会碰诱饵页。要测 Nuclei 的误报，得让它去打这些目标（见下）。

## 能表达与不能表达的

Nuclei 的强项是「一次请求 + 响应匹配」，弱项是需要状态、多步交互，
以及**载荷语法与模板语法冲突**的场景。

| 场景 | 能否用模板表达 | 说明 |
|---|---|---|
| sqli / xss / lfi / xxe / ssrf / cmdi | 能 | 一条请求 + 确定性标记 |
| jwt | 能 | 伪造 alg=none / 弱密钥 token，匹配通关凭证 |
| idor / idor-session | 能 | 已知订单号 + 伪造 cookie，匹配他人数据标记 |
| upload | 能（单步） | 匹配「上传成功」；「落地后能否执行」需要第二步 |
| unserialize | 能（两步） | POST 写文件 + GET 读落地文件，用 `req-condition` 串联 |
| **ssti** | **不能** | `{{ }}` 是 Nuclei 自己的变量语法；用 hex_decode 拼花括号会被二次求值，发出去的是 699 而不是载荷，判据退化成回显 |
| csrf（high） | 不能 | 需要会话绑定的 token，无状态模板拿不到 |

SSTI 这一条值得单独说：第一版模板「命中」了，但把请求体 dump 出来才发现
发的是求值后的 `699`。**这正是本基准研究的误报类型** —— 判据把回显当执行。
发现后删掉了这两条模板，宁可少两条覆盖，也不留假阳性。

## 自己写模板的偏置

这 24 个模板由靶场作者编写，天然知道「打哪里、匹配什么」。
所以 92.3% 的 TPR 只能说明**模板覆盖了 24 个正例**，
不能说明 Nuclei 在未知目标上的检出能力。论文里必须把这条写进效度威胁，
不能拿它当「Nuclei 的检出率」。

## 怎么跑

```bash
# 1) 起靶场
php -S 127.0.0.1:8080 -t html
php -S 127.0.0.1:8090 -t html

# 2) 装 Nuclei（任意版本 >= 3.x），或设置 NUCLEI_BIN
export NUCLEI_BIN=/path/to/nuclei

# 3) 评测
python benchmark/harness/evaluate.py --scanner nuclei --url http://127.0.0.1:8080
```

适配器在 `benchmark/harness/adapters/nuclei.py`，负责起进程、读 JSONL、
把 `matched-at` / `template-id` 归一成统一的 finding 结构。

## 三个踩过的坑

**`-ni` 不是可选参数。** 不加时 Nuclei 会等 stdin 输入目标，脚本里表现为
「打完 banner 就不动了」，超时后连结果文件都没有。

**`{{ }}` 会被 Nuclei 当模板变量。** 除了 SSTI 无法表达之外，这也解释了
为什么不能拿「命中数」直接当覆盖数：先 dump 请求体，确认发出去的是你以为的载荷。

**YAML 里的引号与反斜杠。** 正则里的 `\s` 放在双引号里会被当成非法转义，
含 `"` 的匹配串要用单引号。这两类错误 Nuclei 只在加载时 WRN 一行，
不 `-validate` 很容易漏掉，表现为「模板写了但从不命中」。

## 与官方模板库的关系

本目录不 vendor 官方模板库（几万条、上百 MB），也不在 CI 里跑 Nuclei
（Windows 二进制、体积大）。CI 只做静态校验：
`tests/test_nuclei_templates.py` 检查 id 与文件名一致、YAML 合法、
首个请求落在 low/medium 正例路径上、多步请求的后续目标只能是落地文件。
