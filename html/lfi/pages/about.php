<?php
/**
 * 「关于」页面 —— 文件包含场景里的一个正常目标。
 *
 * 这类页面本身没有漏洞，它的作用是给 LFI 提供一个「合法路径的对照组」：
 * 你既可以用它确认功能正常，也可以用它和穿越后的结果做对比。
 */
?>
<div class="card">
  <h3 style="margin-top:0">关于 VulnLab</h3>
  <p style="font-size:14px;color:var(--muted);margin:0 0 10px">
    这是一个用 PHP 从零写成的 Web 漏洞靶场，覆盖 OWASP Top 10 的主要类别。
  </p>
  <p style="font-size:14px;color:var(--muted);margin:0">
    每个漏洞都提供三档难度、完整 Writeup、机读 PoC 与修复对照 ——
    <b>不只教怎么打，还教怎么修。</b>
  </p>
</div>

<div class="card tight">
  <div style="font-size:13px;color:var(--muted);margin-bottom:8px">
    当前包含的页面（由文件包含机制加载）
  </div>
  <div class="kv"><b>about</b><span class="mono">本页</span></div>
  <div class="kv"><b>contact</b><span class="mono">联系方式示例</span></div>
  <div class="kv"><b>help</b><span class="mono">帮助说明</span></div>
</div>
