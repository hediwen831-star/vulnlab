# Nuclei 接入：13 个模板与被测边界

## 这是什么

`templates/` 下 13 个 Nuclei 模板，一一对应 VulnLab 的 13 个 low 档。
它们是**我们自己写的**，不是官方模板库的一部分 —— 官方模板针对真实产品
（WordPress、Jenkins、Spring 等），不覆盖这个靶场的路径。直接跑官方模板
只会得到 0 命中，那不叫「Nuclei 的检出率」，叫「模板没写」。

真正被比较的是：**同一个可表达的检测任务，用不同引擎实现，误报与漏报如何。**

## 实测结果（2026-10-25，基准 91 例）

| 工具 | TPR | FPR | 命中 | 未归属 |
|---|---:|---:|---:|---:|
| nuclei（13 模板） | 50.0%（13/26） | 0.0%（0/65） | 13 | 0 |

- 13 条命中全部落在 low 档，与模板覆盖一一对应；
- 13 个 medium 档全部漏检 —— 模板没写，不是引擎的问题；
- 65 条负例零误报，但**这个 0 的说服力有限**：模板只打 low 路径，
  本来就不会碰到 high 档。要测 Nuclei 的误报，得让它去打 high 档（见下）。

## 能表达与不能表达的

Nuclei 的强项是「一次请求 + 响应匹配」，弱项是需要状态或多步交互的场景。

| 场景 | 能否用模板表达 | 说明 |
|---|---|---|
| sqli / xss / lfi / xxe / ssrf / cmdi / ssti | 能 | 一条请求 + 确定性标记 |
| jwt | 能 | 伪造 alg=none 的 token，匹配通关凭证 |
| idor / idor-session（low） | 能 | 已知订单号 + 匹配他人数据标记 |
| upload | 能（单步） | 匹配「上传成功」；「落地后能否执行」需要第二步 |
| unserialize | 能（两步） | POST 写文件 + GET 读落地文件，用 `req-condition` 串联 |
| csrf（medium/high） | 不能 | 需要会话绑定的 token，无状态模板拿不到 |
| 带状态的越权（换 cookie） | 不能 | 需要会话管理，Nuclei 的 cookie 复用不保证隔离 |

「能表达」不等于「这次写了」：本目录只有 low 档的 13 个模板，
medium 档需要另写 13 个（绕过 payload 不同），属于后续工作。

## 自己写模板的偏置

这 13 个模板由靶场作者编写，天然知道「打哪里、匹配什么」。
所以 50% 的 TPR 只能说明**模板覆盖了 13 个 low 档**，
不能说明 Nuclei 在未知目标上的检出能力。论文里必须把这条写进效度威胁，
不能拿它当「Nuclei 只有 50%」的证据。

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

## 两个踩过的坑

**`-ni` 不是可选参数。** 不加时 Nuclei 会等 stdin 输入目标，脚本里表现为
「打完 banner 就不动了」，超时后连结果文件都没有。第一次接的时候就栽在这。

**`{{ }}` 会被 Nuclei 当模板变量。** SSTI 的 `{{ 233*3 }}` 直接写进 body
会报 `unresolved variables found`，请求根本发不出去。解法是用
`{{hex_decode('7b7b')}}` 在运行时拼出 `{{`，让它在变量解析之后才出现。

## 与官方模板库的关系

本目录不 vendor 官方模板库（几万条、上百 MB），也不在 CI 里跑 Nuclei
（Windows 二进制、体积大）。CI 只做静态校验：
`tests/test_nuclei_templates.py` 检查 id 与文件名一致、YAML 合法、
首个请求落在 low 档路径上、多步请求的后续目标只能是落地文件。
