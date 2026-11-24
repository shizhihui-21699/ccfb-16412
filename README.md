# libsubsafe — 加固的外挂字幕解析库

一个用 C++17 编写、面向桌面视频播放器的**安全字幕解析库**。它把十几种外挂字幕
格式当作完全不可信的输入，在统一的有界读取层和样式沙箱之后，向渲染器交付干净、
有界、归一化的字幕数据。

> 设计目标：**无论字幕文件如何恶意构造，解析过程都不会越界读写、不会耗尽内存、
> 不会让播放器崩溃。** 单条字幕出错只丢这一条，其余照常显示。

---

## 1. 威胁模型与对策

历史上字幕解析的可利用缺陷集中在三类输入，本库逐一在边界处拦截：

| 攻击面 | 典型恶意构造 | 本库对策 |
| --- | --- | --- |
| 超长样式定义 | MB 级 `Style:` 行、单条巨型样式 run | 统一 `Budget` 字节预算 + 每字段/每行/每条字幕硬上限；任何增长先记账 |
| 畸形时间轴 | 整数溢出的时间值、负时间、end<start、超范围小时 | 手写溢出感知的数字解析（不用 `strtol`/`scanf`）；`__int128` 累加；钳制与自动修复 |
| 嵌入字体 / 样式脚本 | `[Fonts]` 二进制炸弹、`\move`/`\t` 动画、`\p` 绘图、`<script>`、`javascript:` | 默认拒绝的样式能力沙箱；字体仅作有界裸字节保留，绝不加载执行 |

额外的横向防护：

- **输入硬上限**：超过 `maxInputBytes` 在解码前直接拒绝（解压炸弹）。
- **行数 / 条目 / 诊断数全部有界**：诊断列表自身也不能被用来 OOM。
- **UTF-8 修复 + NUL/C0/C1 控制字符清除**：嵌入 NUL 无法截断字符串处理。
- **嵌套深度限制**：JSON 递归下降带显式深度计数，杜绝栈耗尽。
- **`noexcept` 边界**：`parse()` 捕获包括 `std::bad_alloc` 在内的一切异常，转成
  `Fatal` 诊断并返回已抢救出的部分结果。播放器热路径无需 `try/catch`。

---

## 2. 目录结构

```
include/subsafe/
  types.h          公共数据类型（Cue / FontData / Format）
  limits.h         可调资源上限、诊断与 ParseResult 契约
  style_policy.h   样式能力策略（沙箱开关与数值钳制范围）
  subsafe.h        门面：格式探测 + 永不抛出的 parse()
  capi.h           纯 C ABI（供 C / 其他语言 FFI）
src/
  internal/        BoundedReader、Budget、有界数字/时间解析、UTF-8 修复
  parsers_*.cpp    各格式解析器
  style_policy.cpp ASS  override 沙箱 + HTML 内联标签消毒
  facade.cpp       格式自动探测与异常兜底
  capi.cpp         C ABI 实现
tests/             功能 / 对抗 / 性能测试 + fuzz 目标
tools/             subsafe-check 命令行风险检查器
examples/          良性与恶意样本、播放器集成示例
```

## 3. 支持的格式（13 种）

SubRip (`.srt`)、WebVTT (`.vtt`)、ASS (`.ass`)、SSA (`.ssa`)、MicroDVD (`.sub`)、
SAMI (`.smi`)、Phoenix (`.psb`)、TED 风格 JSON、YouTube SBV、歌词 LRC、MPL2、
TMP，以及 `Format::Auto` 自动探测。

## 4. 快速使用

### C++

```cpp
#include "subsafe/subsafe.h"
using namespace subsafe;

ParserLimits lim = ParserLimits::defaults();      // 已经足够保守
StylePolicy pol = StylePolicy::defaultPolicy();   // 危险能力默认关闭
ParseResult r = parse(bytes, size, lim, pol);     // noexcept，绝不抛出
for (const Cue& c : r.cues) {
    // c.startMs <= c.endMs，均在时间轴上限内；c.text 已消毒且有界
}
```

### 纯 C

```c
#include "subsafe/capi.h"
subsafe_result_t* r = subsafe_parse(data, n, SUBSAFE_FMT_AUTO,
                                    /*allow_fonts=*/0, /*allow_drawing=*/0);
for (size_t i = 0; i < subsafe_result_cue_count(r); ++i) {
    const subsafe_cue_t* c = subsafe_result_get_cue(r, i);
}
subsafe_result_free(r);
```

### 命令行

```bash
subsafe-check [--strict] [--allow-fonts] [--json] <file>...
```

---

## 5. 样式沙箱能力策略

`StylePolicy` 默认在**保留良性样式**与**拒绝危险能力**之间取得平衡，确保海量历史
字幕的正常显示不受影响：

- 默认**剥离**：`\move`、动画变换 `\t`、矢量绘图 `\p`、嵌入字体、HTML
  `<script>/<object>/<svg>`、`on*=` 事件、`javascript:/vbscript:/data:` URI。
- 默认**保留**：粗斜下划线、颜色、对齐 `\an`、换行 `\N`、卡拉OK计时 `\k`。
- 即使在 `permissive()` 宽松策略下，**所有数值仍被钳制**：坐标不超过
  `maxCoordPx`、字号限制在 `[minFontSize, maxFontSize]`、模糊半径折叠到
  `maxEffectRadiusPx`，渲染器永远不会收到能驱动巨型分配的标量。

## 6. 构建与测试

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build

# 内存安全验证（AddressSanitizer + UndefinedBehaviorSanitizer）
cmake -S . -B build-asan -DSUBSAFE_ASAN=ON
cmake --build build-asan -j
ctest --test-dir build-asan

# 对语料做一次性崩溃复现（无需特殊引擎，任何工具链都可构建）
./build-asan/tests/fuzz_repro corpus/*

# 真正的 libFuzzer 持续模糊（需要工具链带 fuzzer 运行时，如 Linux clang）
cmake -S . -B build-fuzz -DSUBSAFE_FUZZ=ON
cmake --build build-fuzz
./build-fuzz/tests/fuzz_subtitle corpus/ -max_total_time=300
```

> 注：`LLVMFuzzerTestOneInput` 在所有 clang 上都能完成插桩编译；若某个工具链只缺
> fuzzer 运行时库（例如仅含 Command Line Tools 的 macOS），用 `fuzz_repro` 走相同的
> `exercise()` 不变量断言即可，二者对每个输入执行完全一致的校验逻辑。

## 7. 性能

解析与输入规模线性相关，无回溯/二次复杂度。参考数据（Apple Silicon，Release）：

- 2 万条带 override 的密集特效 ASS 事件：约 36 ms（约 60 MB/s）。
- 20 万个畸形未闭合括号：约 0.8 ms。
- 数据量 4 倍时耗时约 3.6 倍，验证线性。

这让整轨字幕可以在打开视频时一次性解析，且解析与渲染解耦——渲染器只看到已经
消毒、定长的结果，特效字幕的逐帧性能不受解析影响。

## 8. 故障契约

- 解析器**不向调用方抛异常**；所有问题进入 `ParseResult::diagnostics`。
- 严重级别 `Note/Warning/Error/Fatal`；非 Fatal 时返回所有可抢救的 cue。
- 触发任何上限都会置 `limitHit=true`，便于播放器上报遥测。
- 指针输入为 null、输入超大、深度超限等均有明确的 Fatal 诊断码。
