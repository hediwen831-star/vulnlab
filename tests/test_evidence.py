"""证据构造的单测（离线）。

这里守的是两个容易出错、又直接影响实验结论的点：
档位脱敏是否彻底，以及多出现位置里能不能挑出「结果区」那处。
第一版没有挑，模型看到的永远是输入框回填，把真漏洞全判成了误报。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmark.harness.evidence import _marker, _score, mask_tier  # noqa: E402

BODY = """
<div class="card">
  <form><input type="text" name="id" value="-1 UNION SELECT 1,'VULNLAB_X',3,4"></form>
  <div class="sqlbox">SELECT id FROM users WHERE id = -1 UNION SELECT 1,'VULNLAB_X',3,4</div>
  <h3>查询结果</h3>
  <table><tbody><tr><td class="mono">VULNLAB_X</td></tr></tbody></table>
</div>
"""

MULTI = "<input value=\"VULNLAB_X\"> <h3>命令输出</h3> <pre>ping ok\nVULNLAB_X</pre>"


def test_mask_tier_removes_answers() -> None:
    text = "http://h/sqli/high.php 页面标题：SQL 注入 · 难度 high（已修复）"
    masked = mask_tier(text)
    assert "high" not in masked
    assert "已修复" not in masked
    assert "/target.php" in masked


def test_marker_ignores_site_name() -> None:
    body = "<title>VulnLab</title><td>VULNLAB_POC_MARKER</td>"
    assert _marker("http://h/x.php?id=VULNLAB_POC_MARKER", body) == "VULNLAB_POC_MARKER"
    # 裸 VULNLAB 不算标记：标题里就有
    assert _marker("http://h/x.php", "<title>VulnLab</title>") == ""


def test_score_prefers_result_region() -> None:
    input_idx = BODY.index("VULNLAB_X")
    result_idx = BODY.index('class="mono">VULNLAB_X')
    form_window = BODY[max(0, input_idx - 200) : input_idx + 200]
    result_window = BODY[max(0, result_idx - 200) : result_idx + 200]

    assert _score(result_window, result_idx, BODY) > _score(form_window, input_idx, BODY)


def test_multi_occurrence_covers_output_block() -> None:
    # 结果区那处应当得分不低于表单回填那处
    form_idx = MULTI.index("VULNLAB_X")
    out_idx = MULTI.index("VULNLAB_X", form_idx + 1)
    form_window = MULTI[max(0, form_idx - 100) : form_idx + 100]
    out_window = MULTI[max(0, out_idx - 100) : out_idx + 100]
    assert _score(out_window, out_idx, MULTI) >= _score(form_window, form_idx, MULTI)
