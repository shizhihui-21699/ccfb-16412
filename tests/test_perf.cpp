// SPDX-License-Identifier: MIT
// Performance / linearity tests. The parser must stay comfortably within a
// playback frame budget even for dense effects subtitles, and its cost must
// scale linearly (never super-linearly) with input size.
#include "subsafe/subsafe.h"
#include "test_framework.h"

#include <chrono>
#include <cstdio>
#include <string>

using namespace subsafe;
using clock_ = std::chrono::steady_clock;

static double msSince(clock_::time_point t0) {
    return std::chrono::duration<double, std::milli>(clock_::now() - t0).count();
}

// Build a realistic dense ASS file: n dialogue events with inline override
// blocks including karaoke and styling, mirroring a fansub effects track.
static std::string buildAss(size_t events) {
    std::string s =
        "[Script Info]\nPlayResX:1920\nPlayResY:1080\n\n[V4+ Styles]\n"
        "Format: Name, Fontname, Fontsize\nStyle: Default,Arial,48\n\n"
        "[Events]\nFormat: Layer, Start, End, Style, Name, MarginL, "
        "MarginR, MarginV, Effect, Text\n";
    for (size_t i = 0; i < events; ++i) {
        int sec = int(i % 3000);
        s += "Dialogue: 0,";
        s += "0:00:";
        s += (sec < 10 ? "0" : "");
        s += std::to_string(sec) + ".00,0:00:";
        s += std::to_string(sec) + ".50,Default,,0,0,0,,";
        s += "{\\an8\\k20\\b1\\c&H00FF00&}Line ";
        s += std::to_string(i) + " {\\i1}effect{\\r}\\Nnext line\n";
    }
    return s;
}

TEST(perf_dense_ass_throughput) {
    std::string big = buildAss(20000);
    auto t0 = clock_::now();
    auto r = parse(big);
    double elapsed = msSince(t0);

    CHECK_EQ(r.cues.size(), size_t(20000));
    // 20k dense events should parse in well under one second on any CI box;
    // this is a generous bound, the real number is far lower.
    std::printf("    20k ASS events: %.1f ms (%.1f MB/s)\n", elapsed,
                double(big.size()) / (elapsed * 1024.0));
    CHECK(elapsed < 1000.0);
}

TEST(perf_linear_scaling) {
    std::string a = buildAss(5000);
    std::string b = buildAss(20000);   // 4x the cues
    auto t0 = clock_::now();
    parse(a);
    double ta = msSince(t0);
    t0 = clock_::now();
    parse(b);
    double tb = msSince(t0);
    // Allow generous slack (8x) so the assertion guards against quadratic
    // blowups rather than micro-benchmark noise.
    std::printf("    5k: %.2f ms, 20k: %.2f ms, ratio %.2fx\n",
                ta, tb, tb / (ta + 0.001));
    CHECK(tb < ta * 8.0 + 50.0);
}

TEST(perf_malformed_no_quadratic) {
    // Repeated unbalanced braces / unclosed tags are a classic quadratic
    // regex-DoS vector; ensure bounded behavior.
    std::string s = "1\n00:00:01,000 --> 00:00:02,000\n";
    for (int i = 0; i < 200000; ++i) s += "{\\b1 ";
    auto t0 = clock_::now();
    auto r = parse(s);
    double elapsed = msSince(t0);
    std::printf("    200k unbalanced braces: %.1f ms\n", elapsed);
    CHECK(elapsed < 1000.0);
    CHECK(!r.cues.empty());
}

RUN_ALL_TESTS()
