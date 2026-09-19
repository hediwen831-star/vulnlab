<?php
/**
 * 路径工具 —— 把绝对路径换算成「相对于当前工作目录」的写法。
 *
 * ══════════════════════════════════════════════════════════════════
 * 为什么需要这个
 * ══════════════════════════════════════════════════════════════════
 *
 * 反序列化场景里，攻击者要控制的是 `FileStore::$dir`，而 `write()` 用的是：
 *
 *     file_put_contents($this->dir . $key, $value)
 *
 * **相对路径是相对于「当前工作目录」解析的** —— 而 CWD 是什么，
 * 取决于 PHP 是怎么跑起来的：
 *
 *   · PHP 内置服务器（本项目默认方式）
 *       → 会把 CWD 切到**被请求脚本所在目录**
 *         请求 /unserialize/low.php 时，CWD = html/unserialize/
 *
 *   · Apache / Nginx + FPM
 *       → CWD 通常是站点根目录或进程启动目录，和上面不一样
 *
 * 所以同一份 payload，在不同部署方式下相对路径的写法是**不一样的**。
 * 如果页面只写「写到 uploads 目录」，使用者按字面构造 `html/uploads/`
 * 会发现文件根本没落盘 —— 而且因为 `write()` 里用了 `@` 抑制错误，
 * **不会有任何报错**，只会看到「没有新文件」。
 *
 * 与其让人猜，不如把答案直接显示出来：本文件负责在运行时算出
 * 「从当前工作目录走到 uploads/ 该怎么写」，页面再把它展示给使用者。
 *
 * 这样无论跑在内置服务器还是 Apache 下，页面上给出的路径都是对的。
 */

declare(strict_types=1);

/**
 * 判断字符串里是否含有 null 字节（`\0`）。
 *
 * ══════════════════════════════════════════════════════════════════
 * 为什么这个检查不能省
 * ══════════════════════════════════════════════════════════════════
 *
 * null 字节截断是「路径/文件名处理」里的一个经典坑：
 *
 *   · 旧版 PHP（< 5.3.4）里 `\0` 会**截断字符串** ——
 *     `include "safe.php\0../../../etc/passwd"` 会被当成 `safe.php`
 *     送进内核，而内核只认前半段 → 绕过所有基于字符串的路径校验。
 *
 *   · 现代 PHP 已经修掉了截断行为：内部函数在参数解析阶段发现
 *     `\0` 会**拒绝**这次调用。
 *
 * ⚠️ 但「拒绝」的形式取决于 `declare(strict_types=1)`：
 *
 *     · 非严格模式 → 发一条 Warning，函数返回 false/NULL
 *     · **严格模式** → 直接抛 `TypeError`
 *
 * 而 `@` 运算符**只压 Warning，压不住抛出的 Error** ——
 * 于是「加了 @ 的那一行」在严格模式下会变成未捕获的致命错误，
 * 响应里带上完整的绝对路径和调用栈。
 *
 * 本靶场所有页面都声明了 `strict_types=1`，所以必须显式挡掉 `\0`，
 * 而不是指望 `@` 能兜住。
 *
 * @param string $value 待检查的字符串（路径、URL、文件名都算）
 */
function contains_null_byte(string $value): bool
{
    return strpos($value, "\0") !== false;
}

/**
 * 计算从「当前工作目录」到目标目录的相对路径。
 *
 * @param string $destDir 目标目录（绝对路径，可以是 Windows 或 Unix 风格）
 *
 * @return string 以 `/` 结尾的相对路径；若两者不在同一盘符下，则返回绝对路径
 *
 * 例：CWD = `.../vulnlab/html/unserialize`，dest = `.../vulnlab/html/uploads`
 *     → `../uploads/`
 */
function relative_dir_from_cwd(string $destDir): string
{
    $normalize = static function (string $path): string {
        // 统一分隔符，再去掉末尾多余的斜杠（保留根目录本身的斜杠）
        $path = str_replace('\\', '/', $path);
        $trimmed = rtrim($path, '/');
        return $trimmed === '' ? '/' : $trimmed;
    };

    $cwd = $normalize((string) getcwd());
    $dest = $normalize($destDir);

    // Windows 下如果不在同一个盘符，压根算不出相对路径 —— 直接用绝对路径
    $drive = static function (string $path): string {
        return preg_match('#^([A-Za-z]:)/#', $path, $m) === 1 ? strtolower($m[1]) : '';
    };
    if ($drive($cwd) !== $drive($dest)) {
        return $dest . '/';
    }

    $cwdParts = $cwd === '/' ? [] : explode('/', trim($cwd, '/'));
    $destParts = $dest === '/' ? [] : explode('/', trim($dest, '/'));

    // 找到第一个不同的层级
    $same = 0;
    while (
        $same < count($cwdParts)
        && $same < count($destParts)
        && $cwdParts[$same] === $destParts[$same]
    ) {
        $same++;
    }

    // 从 CWD 回到公共祖先需要几级 `..`
    $up = array_fill(0, count($cwdParts) - $same, '..');
    // 再从公共祖先往下走到目标
    $down = array_slice($destParts, $same);

    $rel = implode('/', array_merge($up, $down));

    if ($rel === '') {
        return './';
    }

    return $rel . '/';
}

/**
 * 把「该往 $dir 里写什么」直接渲染到页面上。
 *
 * 这个提示是有意给出的 —— 本场景要练的是 **POP 链怎么构造**，
 * 而不是「猜 PHP 的工作目录是什么」。后者是环境的偶然属性，
 * 猜错了只会得到一句「没有新文件」，学不到任何东西。
 *
 * @param string $targetDir 目标目录的绝对路径
 * @param string $label     展示用的名字
 */
function render_target_dir_hint(string $targetDir, string $label = 'uploads'): void
{
    $cwd = (string) getcwd();
    $rel = relative_dir_from_cwd($targetDir);
    ?>
    <p class="hint" style="margin:12px 0 0">
      <b>写入位置提示</b>：
      <code>$dir</code> 是按「<b>当前工作目录</b>」解析的，不是按网页根目录。<br>
      本页的工作目录是 <code><?= htmlspecialchars(str_replace('\\', '/', $cwd)) ?></code>，
      所以走到 <code><?= htmlspecialchars($label) ?></code> 目录要写成
      <code><?= htmlspecialchars($rel) ?></code> —— 直接用这个值填 <code>$dir</code> 即可。
      <br>
      <span style="opacity:.75">
        （为什么要专门说这件事：路径写错时 <code>file_put_contents()</code> 只是返回 false，
        而靶场代码里用了 <code>@</code> 抑制报错，所以不会有任何提示 ——
        只会看到「没有新文件」。这类静默失败在真实排错里也是常见坑。）
      </span>
    </p>
    <?php
}
