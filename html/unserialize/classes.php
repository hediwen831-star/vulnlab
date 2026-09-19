<?php
/**
 * PHP 反序列化场景的类定义 —— 三档共用。
 *
 * ══════════════════════════════════════════════════════════════════
 * 反序列化漏洞的本质：**对象的属性可以被攻击者控制**
 * ══════════════════════════════════════════════════════════════════
 *
 * 这个场景和前面几个不太一样，它演示的是一类**结构性问题**：
 *
 *   `unserialize()` 能把一串字符串还原成对象，而**字符串里包含了
 *   对象的类名和全部属性值** —— 也就是说，攻击者可以凭空构造出一个
 *   他从未"创建"过的对象，并直接指定它的每一个字段。
 *
 *   如果这个类的某个**魔术方法**（`__destruct` / `__wakeup` / `__toString`）
 *   会拿这些属性去做危险操作（写文件、执行命令、发请求），
 *   那么"反序列化一个字符串"就等于"让服务器执行一段操作"。
 *
 * 这就是所谓的 **POP 链**（Property-Oriented Programming）：
 * 不需要注入代码，只需要**把对象的属性串起来**，让现有的方法互相调用。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 *
 * ── 关于属性声明写法 ──────────────────────────────────────────────
 *
 * 这里用的是 `@var` 注解 + 无类型属性这种**老写法**，
 * 而不是更现代的带类型属性声明 —— 因为**属性类型声明是 PHP 7.4 才引入的**，
 * 在 7.2/7.3 上会直接 Parse error。
 *
 * 靶场的目标运行环境是 PHP 7.2+（很多老站点和 CTF 环境都停在这个版本），
 * 所以源码里统一避开 7.4 之后的语法。
 */

declare(strict_types=1);

/**
 * 文件存储 —— POP 链的**终点**（sink）。
 *
 * 它的 `write()` 会拼接目录和文件名后写文件。单独看这个方法，
 * 它只是个普通的工具方法 —— 问题在于**它会被反序列化过程自动调用**。
 */
class FileStore
{
    /** @var string 写文件的目标目录 —— 可被反序列化控制 */
    public $dir = '/tmp/';

    public function write(string $key, string $value): bool
    {
        // 危险点：目录来自对象属性，而这个属性可以被反序列化控制
        $target = $this->dir . $key;
        return @file_put_contents($target, $value) !== false;
    }
}

/**
 * 缓存对象 —— POP 链的**中间节点**。
 *
 * 它会持有另一个对象（`$store`），并在析构时调用它的 `write()`。
 * 这样就把「反序列化」和「写文件」连接起来了。
 */
class Cache
{
    /** @var string */
    public $key = 'cache_key';

    /** @var string */
    public $value = 'cache_value';

    /** @var mixed 一个"存储后端"对象 */
    public $store = null;

    /**
     * 析构函数在**对象被销毁时**自动调用。
     *
     * 关键点：`unserialize()` 出来的对象在脚本结束时会被销毁 ——
     * 也就是说，**只要反序列化成功，__destruct 就会执行**，
     * 不需要任何额外的触发动作。
     *
     * 这是反序列化漏洞最"顺"的地方：攻击者不需要诱导某个功能被调用，
     * 反序列化这个动作本身就完成了触发。
     */
    public function __destruct()
    {
        if (is_object($this->store) && method_exists($this->store, 'write')) {
            $this->store->write($this->key, $this->value);
        }
    }
}

/**
 * 日志对象 —— 一个**看起来无害**的类。
 *
 * 它演示的是「魔术方法链」：`__toString` 在对象被当成字符串时触发，
 * 于是可以把调用链延伸到意想不到的地方。
 */
class Logger
{
    /** @var string */
    public $prefix = '[LOG] ';

    /** @var mixed 被"记录"的东西 —— 会被转成字符串 */
    public $subject = '';

    public function __toString(): string
    {
        // 把 subject 转成字符串 —— 如果它也是个对象，
        // 就会触发那个对象的 __toString，形成链式调用
        return $this->prefix . (string) $this->subject;
    }
}

/**
 * 演示用的「无害」类 —— 供 medium 档的白名单做对照。
 */
class SafeNote
{
    /** @var string */
    public $text = '';

    public function __toString(): string
    {
        return $this->text;
    }
}
