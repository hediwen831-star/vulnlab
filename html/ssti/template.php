<?php
/**
 * 极简模板引擎 —— SSTI 场景三档共用。
 *
 * ══════════════════════════════════════════════════════════════════
 * 这个文件的定位：一个「看起来很正常」的轻量模板实现
 * ══════════════════════════════════════════════════════════════════
 *
 * 真实的 SSTI 漏洞很少出现在 Twig / Smarty / Blade 这些成熟引擎上 ——
 * 它们默认就有沙箱、有转义、有明确的设计边界。
 *
 * SSTI 更多出现在**自己手写的轻量模板**里，比如：
 *
 *   · 后台的「通知模板」功能，让运营填一段带占位符的文案
 *   · 报表系统里的「自定义字段」，允许写简单的表达式
 *   · 各种「配置即代码」的小功能
 *
 * 这类实现往往只有十几行，思路是：
 *
 *     用正则找到 {{ ... }}，把里面的内容当表达式求值
 *
 * 求值这一步最省事的写法就是 `eval('return ' . $expr . ';')`。
 * **这十几行就是 SSTI 的完整成因。**
 *
 * ── 为什么这不是「一个普通的字符串替换」 ──
 *
 * 在开发者眼里，`{{ }}` 里应该是「一个数字」「一个变量名」。
 * 但 `eval` 不理解这个意图 —— 它执行的是**任意 PHP 表达式**。
 * 于是：
 *
 *     {{ 7*7 }}                    → 49            看起来完全符合预期
 *     {{ phpinfo() }}              → 整页环境信息    已经越界了
 *     {{ file_get_contents(...) }}  → 读任意文件
 *     {{ system('id') }}           → 执行任意命令
 *
 * 从「49」到「执行命令」，中间没有任何门槛 ——
 * 因为它们本来就是同一件事：**执行表达式**。
 *
 * 这也解释了为什么 SSTI 的修复不能靠黑名单：
 * 你要枚举的不是「攻击者的写法」，而是「PHP 有多少个函数」——
 * 这个列表有几万个，而且还在增长。
 */

declare(strict_types=1);

/**
 * 扫描模板，找出所有 `{{ 表达式 }}`。
 *
 * @return list<array{0:string,1:int}> 每项为 [表达式, 在模板中的起始偏移]
 */
function ssti_find_expressions(string $template): array
{
    $found = [];
    if (preg_match_all('/\{\{\s*(.+?)\s*\}\}/s', $template, $matches, PREG_OFFSET_CAPTURE) === false) {
        return [];
    }
    foreach ($matches[1] as [$expr, $offset]) {
        $found[] = [(string) $expr, (int) $offset];
    }
    return $found;
}


/**
 * 渲染模板：把每个 `{{ 表达式 }}` 交给 `$evaluate` 求值后替换。
 *
 * ⚠️ 注意这个函数的签名 —— 它接收一个 `callable`。
 * 也就是说：**「怎么求值」这个决定被外置了**，
 * 由调用方（也就是各档页面）决定。这正是本场景三档的差异所在：
 *
 *   low    ：直接 eval
 *   medium ：过滤掉括号之后再 eval
 *   high   ：根本不求值，只做变量替换
 *
 * 同一套模板语法，三种截然不同的安全性 ——
 * 说明**问题不在语法，在「拿它做了什么」**。
 *
 * @param string   $template  模板文本
 * @param callable $evaluate  接收表达式字符串，返回替换后的文本
 */
function ssti_render(string $template, callable $evaluate): string
{
    return (string) preg_replace_callback(
        '/\{\{\s*(.+?)\s*\}\}/s',
        static function (array $m) use ($evaluate): string {
            return (string) $evaluate((string) $m[1]);
        },
        $template
    );
}


/**
 * 「不安全」的求值器 —— low / medium 两档用它。
 *
 * ⚠️ 这是整个场景里唯一有漏洞的函数，请勿在任何真实项目里使用。
 *
 * 用 `ob_start()` 包住 eval 有两个原因：
 *
 *   ① `system()` / `passthru()` 这类函数是**直接打印**结果的，
 *      返回值只是最后一行。不捕获的话输出会跑到页面 HTML 结构外面，
 *      使用者会以为「payload 没生效」，其实已经执行了。
 *
 *   ② 反引号 `` `cmd` `` 等价于 `shell_exec()`，它是**返回**结果的。
 *
 * 两种情况都要照顾到，所以「捕获的输出 + 返回值」拼在一起返回 ——
 * 这也是让使用者能直观看到「我这次到底执行了什么」的前提。
 *
 * @param string $expr 表达式（来自模板里 `{{ }}` 的内容）
 */
function ssti_eval_unsafe(string $expr): string
{
    if (trim($expr) === '') {
        return '';
    }

    ob_start();
    /** @noinspection PhpUsageOfSilenceOperatorInspection */
    $value = @eval('return ' . $expr . ';');
    $printed = (string) ob_get_clean();

    if (is_scalar($value) || $value === null) {
        return $printed . (string) $value;
    }

    // 数组 / 对象就用 print_r 展示，方便观察
    return $printed . print_r($value, true);
}


/** 渲染「表达式清单」卡片，三档共用 —— 让人看清模板里到底有几个表达式 */
function render_ssti_expressions(array $expressions, string $verdict = ''): void
{
    if (!$expressions) {
        return;
    }
    ?>
    <div class="card tight" style="margin-bottom:14px">
      <div style="font-size:13px;color:var(--muted);margin-bottom:10px">
        模板里找到 <?= count($expressions) ?> 个表达式
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th style="width:8%">#</th><th>表达式</th><th style="width:30%">处置</th></tr></thead>
          <tbody>
            <?php foreach ($expressions as $i => [$expr, $offset]): ?>
              <tr>
                <td><?= $i + 1 ?></td>
                <td class="mono" style="word-break:break-all"><?= htmlspecialchars($expr) ?></td>
                <td style="font-size:13px;color:var(--muted)">
                  <?= $verdict !== '' ? htmlspecialchars($verdict) : '—' ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php
}
