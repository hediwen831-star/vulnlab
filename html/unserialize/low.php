<?php
/**
 * PHP 反序列化 · low 档
 *
 * 漏洞成因：把用户输入直接交给 `unserialize()`。
 *
 * ⚠️ 本文件是故意存在漏洞的教学代码，请勿在任何真实项目中使用这套写法。
 */

declare(strict_types=1);

require __DIR__ . '/../config.php';
require __DIR__ . '/../lib/layout.php';
require __DIR__ . '/classes.php';
require __DIR__ . '/../lib/paths.php';   // 用于把「$dir 该写什么」显示到页面上

/** 写入目标目录（演示用，同时也是攻击者想控制的位置） */
const TARGET_DIR = __DIR__ . '/../uploads';

$data = isset($_POST['data']) ? (string) $_POST['data'] : '';
$submitted = ($data !== '');

$dump = '';
$error = '';
$newFiles = [];
$beforeFiles = [];
$writtenFiles = [];

if ($submitted) {
    if (!is_dir(TARGET_DIR)) {
        @mkdir(TARGET_DIR, 0777, true);
    }
    // 记录反序列化前的目录状态，用来对比"这一步有没有产生副作用"
    $beforeFiles = array_diff(scandir(TARGET_DIR) ?: [], ['.', '..']);

    // ------------------------------------------------------------------
    // 漏洞点：直接把用户输入喂给 unserialize
    //
    // 这一行就同时给出了两个能力：
    //   ① 攻击者可以指定**任意类**（字符串里带类名）
    //   ② 攻击者可以指定**该类的任意属性值**
    //
    // 剩下的就看有哪些类定义了魔术方法 —— 那些方法会自动执行。
    // ------------------------------------------------------------------
    try {
        $obj = @unserialize($data);

        if ($obj === false && $data !== 'b:0;') {
            $error = '反序列化失败：字符串格式不合法（或包含未定义的类）。';
        } else {
            $dump = print_r($obj, true);

            // ------------------------------------------------------------------
            // ⚠️ 这一行不能省，否则下面的副作用检查永远看不到变化
            //
            // __destruct 的默认触发时机是「脚本结束时」—— 而那时候响应早就组装
            // 完了。所以如果不显式销毁对象，$afterFiles 会恒等于 $beforeFiles，
            // 页面会一直显示"没有新文件"，即使 payload 其实已经成功写盘。
            //
            // unset($obj) 让引用计数归零，__destruct 立刻执行 ——
            // 检查这才看得到"反序列化这个动作本身造成的副作用"。
            //
            // 这个细节本身也是本场景的一部分：反序列化的危害发生在
            // 「你以为一切都已经结束」之后。
            // ------------------------------------------------------------------
            unset($obj);

            $afterFiles = array_diff(scandir(TARGET_DIR) ?: [], ['.', '..']);
            $newFiles = array_values(array_diff($afterFiles, $beforeFiles));

            // ------------------------------------------------------------------
            // 副作用判定：不只看「多了文件」，还看「刚写了什么」
            //
            // 为什么不能只判断 $newFiles 非空：
            //   POP 链写文件是**覆盖式**的。同一个 payload 跑第二次时，
            //   目标文件已经存在，目录不会「多出」新文件 ——
            //   于是「产生了 N 个新文件」这句永远不会再出现，
            //   看起来就像漏洞消失了。
            //
            // 这个缺陷会**自我污染**：一次成功的检测把自己下一次的判据毁掉。
            // 机读 PoC 是靠页面文案判断命中与否的，所以它会先命中一次、
            // 之后永远零命中 —— 而 CI 断言另有一套载荷，察觉不到。
            //
            // 修法是让判据指向「这一次写入了什么」，而不是「目录多了几个文件」：
            //   把刚刚把写过的文件连同内容一起列出来（内容必须匹配预期标记）。
            //   这样无论新增还是覆盖，判据都成立 —— 幂等。
            // ------------------------------------------------------------------
            foreach ($afterFiles as $f) {
                $path = TARGET_DIR . '/' . $f;
                if (!is_file($path)) {
                    continue;
                }
                $content = (string) @file_get_contents($path);
                // 只看本次 payload 造成的变化：新文件，或内容刚刚变成标记串
                if (in_array($f, $newFiles, true) || strpos($content, 'VULNLAB_') !== false) {
                    $writtenFiles[$f] = $content;
                }
            }
        }
    } catch (Throwable $e) {
        $error = '反序列化时抛出异常：' . $e->getMessage();
    }
}

/** 可用的类（页面上列出来，方便理解 POP 链的"零件"有哪些） */
$availableClasses = [
    'FileStore' => '有 write($key, $value) 方法 —— 会拼接 $dir 和 $key 后写文件',
    'Cache'     => '__destruct 时会调用 $store->write($key, $value)',
    'Logger'    => '__toString 会拼接 $prefix 和 $subject',
    'SafeNote'  => '没有危险方法（对照组）',
];
?>
<?php layout_header(
    'PHP 反序列化 · 难度 low',
    'unserialize() 让攻击者能凭空构造对象 —— 包括它的每一个属性。'
); ?>

<?php render_level_switcher(
    ['low.php' => 'low', 'medium.php' => 'medium', 'high.php' => 'high'],
    basename(__FILE__)
); ?>

<div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
  <h3 style="margin-top:0;color:var(--danger)">⚠️ 本场景风险提示</h3>
  <p style="margin:0;font-size:14px;color:#b91c1c">
    反序列化一旦能形成 POP 链，后果通常是<b>直接写文件 / 执行代码</b>。<br>
    本靶场的链只会写文件到 <code>html/uploads/</code>，请勿构造更危险的链。
  </p>
</div>

<div class="card">
  <h3 style="margin-top:0">这一档的防护</h3>
  <pre style="margin:10px 0 0">$obj = <span class="v">unserialize</span>($data);   <span class="c">// 用户输入直接进来</span></pre>

  <h3>本档目标</h3>
  <p style="margin:0;font-size:14px;color:var(--muted)">
    构造一段序列化字符串，让服务器<b>写出一个文件到 uploads 目录</b>。
    注意：你不需要注入任何代码 —— 只需要把现有类的属性"串"起来。
  </p>
  <?php render_target_dir_hint(TARGET_DIR); ?>
</div>

<div class="card">
  <form method="post" action="low.php">
    <div class="row">
      <textarea name="data" rows="4" style="flex:1;font-family:var(--mono);font-size:13px"
                placeholder='O:5:"Cache":3:{...}'
      ><?= htmlspecialchars($data) ?></textarea>
    </div>
    <div class="row">
      <button type="submit">反序列化</button>
    </div>
  </form>
</div>

<?php if ($submitted): ?>
  <?php if ($error !== ''): ?>
    <div class="card" style="border-color:#fecaca;background:var(--danger-soft)">
      <b style="color:var(--danger)"><?= htmlspecialchars($error) ?></b>
    </div>
  <?php endif; ?>

  <?php if ($dump !== ''): ?>
    <?php render_code_board('反序列化得到的对象结构', trim($dump)); ?>
  <?php endif; ?>

  <div class="card" style="<?= $writtenFiles ? 'border-color:#a7f3d0;background:var(--ok-soft)' : '' ?>">
    <h3 style="margin-top:0">副作用检查（uploads 目录的变化）</h3>
    <?php if ($writtenFiles): ?>
      <p style="margin:0 0 10px;color:var(--ok);font-weight:500">
        ★ 写入成功：<?= count($writtenFiles) ?> 个文件
        <?= $newFiles ? '（本次新增）' : '（覆盖同名文件）' ?> —— POP 链生效
      </p>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>文件名</th><th>大小</th><th>内容预览</th></tr></thead>
          <tbody>
            <?php foreach ($writtenFiles as $f => $content): ?>
              <?php
              $path = TARGET_DIR . '/' . $f;
              $size = is_file($path) ? filesize($path) : 0;
              ?>
              <tr>
                <td class="mono"><?= htmlspecialchars((string) $f) ?></td>
                <td><?= (int) $size ?> B</td>
                <td class="mono" style="word-break:break-all;font-size:12px">
                  <?= htmlspecialchars(substr($content, 0, 80)) ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php else: ?>
      <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
        本次没有新文件 —— 有两种可能，别急着下结论：
      </p>
      <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
        <li>对象链里<b>没有触达写文件那个方法</b> —— payload 还需要调整</li>
        <li>其实写成功了，但用的是<b>已存在的文件名</b> ——
            覆盖同名文件不会让目录多出"新"文件。
            换个 <code>$key</code> 再提交一次就能确认</li>
      </ul>
      <?php render_file_list_note(array_values(array_diff(scandir(TARGET_DIR) ?: [], ['.', '..']))); ?>
    <?php endif; ?>
  </div>
<?php endif; ?>

<div class="card">
  <h3 style="margin-top:0">可用的类（POP 链的"零件"）</h3>
  <p style="margin:0 0 10px;font-size:14px;color:var(--muted)">
    源码见 <a href="../source.php?file=unserialize/classes.php">classes.php</a>。
    构造 payload 前先读一遍它们的属性和魔术方法。
  </p>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:18%">类名</th><th>说明</th></tr></thead>
      <tbody>
        <?php foreach ($availableClasses as $cls => $note): ?>
          <tr>
            <td class="mono"><?= htmlspecialchars($cls) ?></td>
            <td style="color:var(--muted);font-size:13px"><?= htmlspecialchars($note) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>

<div class="card">
  <h3 style="margin-top:0">思路提示（不给答案）</h3>
  <ul style="margin:0;padding-left:20px;font-size:14px;color:var(--muted);line-height:1.9">
    <li>序列化字符串的格式是什么？每个字段分别代表什么？</li>
    <li>哪个类的哪个方法**会在反序列化后自动执行**？（提示：魔术方法）</li>
    <li>要让那个方法走到「写文件」，需要给它喂什么样的属性值？</li>
    <li>你可以在本地 PHP 里 <code>echo serialize($obj)</code> 生成 payload —— 这不算作弊，真实攻击也是这么做的。</li>
  </ul>
  <p class="hint">完整推导见 <code>writeups/unserialize.md</code>。</p>
</div>

<?php layout_footer(); ?>
