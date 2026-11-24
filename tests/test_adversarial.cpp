// SPDX-License-Identifier: MIT
// Adversarial tests: deliberately malformed and hostile inputs reproducing the
// threat model (oversized style runs, malformed timelines, embedded payloads,
// nesting/recursion bombs, integer overflow). Every case must either parse to
// bounded output or fail cleanly with a diagnostic — never crash/ASan error.
#include "subsafe/subsafe.h"
#include "subsafe/capi.h"
#include "test_framework.h"

#include <cstring>
#include <string>
#include <string_view>

using namespace subsafe;

static std::string repeat(char c, size_t n) { return std::string(n, c); }
static std::string repeat(std::string_view s, size_t n) {
    std::string out;
    out.reserve(s.size() * n);
    for (size_t i = 0; i < n; ++i) out += s;
    return out;
}

// --- 1. A single cue with a gigantic text run must be capped, not overflow.
TEST(adv_huge_cue_text_capped) {
    std::string s = "1\n00:00:01,000 --> 00:00:02,000\n";
    s += repeat('A', 5'000'000);
    s += "\n";
    auto r = parse(s);
    CHECK(!r.cues.empty());
    CHECK(r.cues[0].text.size() <= ParserLimits::defaults().maxCueTextBytes);
    CHECK(r.limitHit);
}

// --- 2. Megabyte-long ASS style definition cannot exhaust memory.
TEST(adv_huge_ass_style_line) {
    std::string s = "[Script Info]\n[V4+ Styles]\nFormat: Name, Fontname\nStyle: ";
    s += repeat('X', 5'000'000);
    s += "\n[Events]\n";
    auto r = parse(s);
    CHECK(r.ok());   // survives, bounded
    CHECK(r.diagnostics.size() >= size_t(1) || r.limitHit || r.cues.empty());
}

// --- 3. Massive numeric fields (integer overflow attempts in timestamps).
TEST(adv_timestamp_integer_overflow) {
    std::string s =
        "1\n99999999999999999999:59:59,999 --> "
        "99999999999999999999999:59:59,999\nx\n";
    auto r = parse(s);
    // The cue is dropped or clamped; no overflow, no crash.
    for (const auto& c : r.cues) {
        CHECK(c.startMs >= 0);
        CHECK(c.endMs >= c.startMs);
        CHECK(c.endMs <= ParserLimits::defaults().maxTimestampMs);
    }
}

// --- 4. Negative and reversed timestamps get repaired, not trusted.
TEST(adv_reversed_and_negative_time) {
    auto r = parse("1\n00:00:05,000 --> 00:00:01,000\nbackwards\n");
    CHECK_EQ(r.cues.size(), size_t(1));
    CHECK(r.cues[0].startMs <= r.cues[0].endMs);  // swapped
}

// --- 5. ASS move/transform tags are stripped under the default policy.
TEST(adv_ass_dangerous_tags_stripped) {
    const char* s =
        "[Script Info]\n[Events]\n"
        "Format: Layer, Start, End, Style, Name, MarginL, MarginR, "
        "MarginV, Effect, Text\n"
        "Dialogue: 0,0:00:01.00,0:00:02.00,Def,,0,0,0,,{\\move(1,2,3,4)"
        "\\t(0,100,\\fscx2000)}{\\an8}hi\n";
    auto r = parse(s);
    CHECK(!r.cues.empty());
    CHECK(r.cues[0].text.find("move") == std::string::npos);
    CHECK(r.cues[0].text.find("\\t") == std::string::npos);
    CHECK(r.cues[0].text.find("an8") != std::string::npos);  // harmless kept
}

// --- 6. Permissive policy keeps move but clamps absurd coordinates.
TEST(adv_ass_move_clamped_when_allowed) {
    StylePolicy p = StylePolicy::permissive();
    const char* s =
        "[Script Info]\n[Events]\n"
        "Format: Layer, Start, End, Style, Name, MarginL, MarginR, "
        "MarginV, Effect, Text\n"
        "Dialogue: 0,0:00:01.00,0:00:02.00,Def,,0,0,0,,{\\move(99999999,0,0,0)}x\n";
    auto r = parse(s, ParserLimits::defaults(), p);
    CHECK(!r.cues.empty());
    CHECK(r.cues[0].text.find("move") != std::string::npos);
    CHECK(r.cues[0].text.find("99999999") == std::string::npos);  // clamped
}

// --- 7. Font size scalars are clamped to a renderable range.
TEST(adv_ass_fontsize_clamped) {
    StylePolicy p = StylePolicy::permissive();
    const char* s =
        "[Script Info]\n[Events]\n"
        "Format: Layer, Start, End, Style, Name, MarginL, MarginR, "
        "MarginV, Effect, Text\n"
        "Dialogue: 0,0:00:01.00,0:00:02.00,Def,,0,0,0,,{\\fs999999}big\n";
    auto r = parse(s, ParserLimits::defaults(), p);
    CHECK(!r.cues.empty());
    CHECK(r.cues[0].text.find("999999") == std::string::npos);
}

// --- 8. HTML <script> body and on* handlers are neutralized.
TEST(adv_html_script_neutralized) {
    auto r = parse(
        "1\n00:00:01,000 --> 00:00:02,000\n"
        "<script>alert(1)</script><b onclick='evil()'>safe</b> text\n");
    CHECK(!r.cues.empty());
    CHECK(r.cues[0].text.find("alert") == std::string::npos);
    CHECK(r.cues[0].text.find("onclick") == std::string::npos);
    CHECK(r.cues[0].text.find("safe") != std::string::npos);
}

// --- 9. javascript: / data: URIs in font attributes are dropped.
TEST(adv_html_javascript_uri) {
    auto r = parse(
        "1\n00:00:01,000 --> 00:00:02,000\n"
        "<font face=\"javascript:alert(1)\" color=\"red\">x</font>\n");
    CHECK(!r.cues.empty());
    CHECK(r.cues[0].text.find("javascript") == std::string::npos);
    CHECK(r.cues[0].text.find("red") != std::string::npos);
}

// --- 10. Deeply nested JSON is rejected at the depth limit, no stack blow.
TEST(adv_json_nesting_bomb) {
    std::string s;
    for (unsigned i = 0; i < 10000; ++i) s += "[1,";
    s += "1";
    for (unsigned i = 0; i < 10000; ++i) s += "]";
    auto r = parse(s);
    CHECK(!r.ok());
    CHECK(r.cues.empty());
}

// --- 11. Deeply nested/garbage ASS braces do not confuse the sanitizer.
TEST(adv_ass_unbalanced_braces) {
    auto r = parse(
        "1\n00:00:01,000 --> 00:00:02,000\n{\\b1 {unterminated run of text\n");
    CHECK(!r.cues.empty());   // returns safely
}

// --- 12. Embedded fonts are ignored unless explicitly enabled.
TEST(adv_embedded_font_default_deny) {
    std::string s = "[Script Info]\n[Fonts]\nfontname: evil.ttf\n";
    s += repeat('A', 100000);
    s += "\n[Events]\n";
    auto r = parse(s);
    CHECK(r.fonts.empty());
}

TEST(adv_embedded_font_capped_when_allowed) {
    StylePolicy p = StylePolicy::defaultPolicy();
    p.allowEmbeddedFonts = true;
    std::string s = "[Fonts]\nfontname: f.ttf\n";
    s += repeat("QUJD", 1'000'000);  // base64-ish
    auto r = parse(s, ParserLimits::defaults(), p);
    for (const auto& f : r.fonts)
        CHECK(f.bytes.size() <= ParserLimits::defaults().maxFontBytes);
    CHECK(r.limitHit || !r.fonts.empty());
}

// --- 13. Many cues hit the cap; diagnostics themselves are bounded.
TEST(adv_cue_and_diagnostic_caps) {
    std::string s;
    for (size_t i = 0; i < 300000; ++i) {
        s += std::to_string(i) + "\n00:00:01,000 --> 00:00:02,000\nx\n\n";
    }
    auto r = parse(s);
    CHECK(r.cues.size() <= ParserLimits::defaults().maxCues);
    CHECK(r.diagnostics.size() <=
          ParserLimits::defaults().maxStoredDiagnostics);
    CHECK(r.droppedCues > 0);
}

// --- 14. Input over the hard size cap is refused before any decoding.
TEST(adv_input_size_cap_refused) {
    ParserLimits lim = ParserLimits::defaults();
    lim.maxInputBytes = 1024;
    std::string s = repeat('1', 1'000'000);
    auto r = parse(s, lim);
    CHECK(!r.ok());
    bool sawFatal = false;
    for (const auto& d : r.diagnostics)
        if (d.severity == Severity::Fatal) sawFatal = true;
    CHECK(sawFatal);
}

// --- 15. Malformed UTF-8 is repaired, never read out of bounds.
TEST(adv_invalid_utf8_repaired) {
    std::string s = "1\n00:00:01,000 --> 00:00:02,000\n";
    s += '\xC0'; s += '\x80';          // overlong NUL
    s += '\xE0'; s += '\x80';          // truncated sequence
    s += "ok\n";
    auto r = parse(s);
    CHECK(!r.cues.empty());
    CHECK(r.cues[0].text.find('\0') == std::string::npos);
}

// --- 16. Embedded NUL cannot truncate C-string handling.
TEST(adv_embedded_nul_removed) {
    std::string s = "1\n00:00:01,000 --> 00:00:02,000\nab";
    s.push_back('\0');
    s += "cd\n";
    auto r = parse(s);
    CHECK(!r.cues.empty());
    CHECK(r.cues[0].text.find('\0') == std::string::npos);
}

// --- 17. Per-line loop cannot be driven to huge iteration counts.
TEST(adv_million_tiny_lines_bounded) {
    std::string s = repeat("\n", 3'000'000);
    auto r = parse(s);
    CHECK(r.limitHit || r.diagnostics.size() >= size_t(1));
}

// --- 18. JSON with exponent/NaN abuse is rejected.
TEST(adv_json_number_abuse) {
    auto r = parse(R"([{"start":1e99999,"text":"x"}])");
    CHECK(r.ok() ? r.cues.empty() : true);  // either rejected or dropped
}

// --- 19. C API never returns null for normal input and frees cleanly.
TEST(adv_capi_survives_garbage) {
    std::string junk = repeat('\xFF', 10000);
    subsafe_result_t* r = subsafe_parse(
        reinterpret_cast<const uint8_t*>(junk.data()), junk.size(),
        SUBSAFE_FMT_AUTO, 0, 0);
    CHECK(r != nullptr);
    // Every returned cue text must be a valid NUL-terminated string.
    for (size_t i = 0; i < subsafe_result_cue_count(r); ++i) {
        const subsafe_cue_t* c = subsafe_result_get_cue(r, i);
        CHECK(c != nullptr);
        CHECK(std::strlen(c->text) <= ParserLimits::defaults().maxCueTextBytes);
    }
    subsafe_result_free(r);
    subsafe_result_free(nullptr);  // must be a no-op
}

// --- 20. Null data pointer is handled, not dereferenced.
TEST(adv_null_pointer) {
    auto r = parse(nullptr, 0);
    CHECK(r.diagnostics.size() >= size_t(1) || r.cues.empty());
    subsafe_result_t* cr = subsafe_parse(nullptr, 5, SUBSAFE_FMT_AUTO, 0, 0);
    CHECK(cr != nullptr);
    CHECK(!subsafe_result_ok(cr));
    subsafe_result_free(cr);
}

// --- 21. Blur radius beyond the policy max is folded down.
TEST(adv_blur_radius_clamped) {
    StylePolicy p = StylePolicy::permissive();
    const char* s =
        "[Script Info]\n[Events]\n"
        "Format: Layer, Start, End, Style, Name, MarginL, MarginR, "
        "MarginV, Effect, Text\n"
        "Dialogue: 0,0:00:01.00,0:00:02.00,Def,,0,0,0,,{\\blur(99999)}x\n";
    auto r = parse(s, ParserLimits::defaults(), p);
    CHECK(!r.cues.empty());
    CHECK(r.cues[0].text.find("99999") == std::string::npos);
}

// --- 22. A malformed cue in the middle does not lose surrounding cues.
TEST(adv_one_bad_cue_keeps_others) {
    auto r = parse(
        "1\n00:00:01,000 --> 00:00:02,000\ngood one\n\n"
        "2\nNOT A TIMESTAMP LINE\nbroken\n\n"
        "3\n00:00:05,000 --> 00:00:06,000\ngood two\n");
    CHECK(r.cues.size() >= size_t(2));
    CHECK(r.cues.front().text == "good one");
    CHECK(r.cues.back().text == "good two");
}

RUN_ALL_TESTS()
