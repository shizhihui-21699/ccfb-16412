# 安全不变量（Security Invariants）

本文档列出 libsubsafe 必须**对任意输入**都成立的性质。它们既被代码结构强制，也被
对抗测试与 fuzz 目标持续验证。修改解析器时若破坏其中任何一条，即视为回归。

## A. 内存安全

1. **没有任何解析器直接持有原始 `data` 指针做下标写入。** 输入只通过
   `BoundedReader` 读取，输出只通过 `Budget`/`appendCapped` 增长。
2. 所有数组/字符串下标在解引用前都有上界比较；不存在由文件整数推导的
   `new[]`/`reserve` 尺寸。
3. 整数运算使用 `__int128` 累加或显式溢出判断（`a > (MAX-b)/10` 模式），
   杜绝有符号溢出 UB 与回绕导致的越界。
4. 字符串视图（`string_view`）只在 `BoundedReader` 生命周期内使用；跨边界保留的
   内容一律拷贝进拥有型 `std::string`，调用返回后不残留对输入缓冲的引用。
5. C ABI 返回的 `const char*` 全部指向结果对象拥有的、NUL 终止的字符串。

## B. 资源有界（所有上限均在 `ParserLimits`，可由播放器收紧）

| 不变量 | 默认上限 |
| --- | --- |
| 输入字节 | 64 MiB（解码前拒绝） |
| 扫描行数 | 2,000,000 |
| cue 数量 | 200,000 |
| 文本总字节预算 | 32 MiB（每次增长前记账） |
| 单条 cue 文本 | 64 KiB |
| 单行 | 1 MiB |
| 样式条目 / 样式名 | 10,000 / 128 B |
| 嵌入字体数量 / 单字体 / 总计 | 64 / 8 MiB / 32 MiB |
| 嵌套深度 | 32 |
| 绘图指令 | 200,000 |
| 存储的诊断条数 | 100（超出只计数） |

## C. 时间轴完整性

1. 每个输出 cue 满足 `0 <= startMs <= endMs <= maxTimestampMs`。
2. `end < start` 被自动交换并产生 `time.reversed` 警告，而不是被信任。
3. 超范围秒/分被钳制；时长超过 `maxCueDurationMs` 被折叠。
4. 帧制格式（MicroDVD/MPL2/PJS）的帧号经溢出检查后再换算毫秒。

## D. 样式脚本能力

1. 未知 ASS 标签**默认拒绝**（default-deny），只有白名单标签透传。
2. `\move`、`\t`、`\p`、嵌入字体在默认策略下剥离；宽松策略下也强制数值钳制。
3. 所有几何/字号/特效标量被钳制到固定区间，渲染器收不到可驱动巨型分配的值。
4. HTML 内联只保留白名单标签与 `<font>` 的 `color/size/face` 属性；
   `<script>/<style>/<object>/<embed>/<iframe>/<svg>` 整体（含 body）丢弃；
   任何含 `javascript:/vbscript:/data:` 的属性值丢弃。
5. 不平衡的 `{}` / `<>` 不会让消毒器进入未定义状态，残留括号按惰性文本处理。

## E. 编码与控制字符

1. 无效 UTF-8、超长编码、代理码点一律替换为 U+FFFD；NUL 被清除。
2. C0（除 `\t \n \r`）与 C1（除 NEL）控制字符不进入输出。
3. UTF-16（带 BOM 或启发式）转码有硬上限，代理解码正确配对。

## F. 可用性（不崩溃）

1. `parse()` 为 `noexcept`；`bad_alloc` 与任何 `std::exception` 都转成 Fatal 诊断。
2. 单条 cue 解析失败仅丢弃该条并计数 `droppedCues`，前后 cue 不受影响。
3. 空输入、纯空白、null 指针、随机字节均返回结构化结果而非崩溃。

## 验证手段

- `tests/test_adversarial.cpp`：22 类针对性恶意构造（含本文件各不变量的反例）。
- `tests/fuzz_subtitle.cpp`：对三种策略组合断言输出不变量，并交叉校验 C ABI。
- 全部测试在 `-fsanitize=address,undefined` 下零告警通过。
- 编译选项启用 `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
  -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2`。
