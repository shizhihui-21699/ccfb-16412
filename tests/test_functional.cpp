// SPDX-License-Identifier: MIT
// Functional tests: every supported format parses a well-formed sample and
// retains correct timing/text, and detection picks the right parser.
#include "subsafe/subsafe.h"
#include "test_framework.h"

using namespace subsafe;

static ParseResult P(std::string_view s, Format f = Format::Auto) {
    return parse(s, ParserLimits::defaults(), StylePolicy::defaultPolicy(), f);
}

TEST(detect_srt) {
    auto r = P("1\n00:00:01,000 --> 00:00:02,500\nHello\n");
    CHECK_EQ(r.format, Format::Srt);
    CHECK_EQ(r.cues.size(), size_t(1));
    CHECK_EQ(r.cues[0].startMs, int64_t(1000));
    CHECK_EQ(r.cues[0].endMs, int64_t(2500));
    CHECK(r.cues[0].text == "Hello");
    CHECK(r.ok());
}

TEST(srt_multiline_and_indices) {
    auto r = P("12\n00:00:01,000 --> 00:00:02,000\nline one\nline two\n\n"
               "13\n00:00:03,000 --> 00:00:04,000\nsecond\n");
    CHECK_EQ(r.cues.size(), size_t(2));
    CHECK(r.cues[0].text == "line one\nline two");
    CHECK_EQ(r.cues[1].startMs, int64_t(3000));
}

TEST(vtt_basic_with_header_and_note) {
    auto r = P("WEBVTT\n\nNOTE this is a note\nspanning lines\n\n"
               "00:00:01.000 --> 00:00:02.000\nHi <b>there</b>\n");
    CHECK_EQ(r.format, Format::WebVtt);
    CHECK_EQ(r.cues.size(), size_t(1));
    CHECK(r.cues[0].text.find("<b>") != std::string::npos);
}

TEST(vtt_position_settings_parsed) {
    auto r = P("WEBVTT\n\n00:00:01.000 --> 00:00:02.000 position:10 line:20\n"
               "X\n", Format::WebVtt);
    CHECK_EQ(r.cues.size(), size_t(1));
    CHECK_EQ(r.cues[0].posX, int32_t(10));
    CHECK_EQ(r.cues[0].posY, int32_t(20));
}

TEST(ass_dialogue_basic) {
    const char* s =
        "[Script Info]\nTitle: t\n\n[V4+ Styles]\n"
        "Format: Name, Fontname, Fontsize\n"
        "Style: Default,Arial,20\n\n[Events]\n"
        "Format: Layer, Start, End, Style, Name, MarginL, MarginR, "
        "MarginV, Effect, Text\n"
        "Dialogue: 0,0:00:01.00,0:00:02.50,Default,,0,0,0,,Hello {\\b1}world\n";
    auto r = P(s);
    CHECK_EQ(r.format, Format::Ass);
    CHECK_EQ(r.cues.size(), size_t(1));
    CHECK_EQ(r.cues[0].startMs, int64_t(1000));
    CHECK_EQ(r.cues[0].endMs, int64_t(2500));
    CHECK(r.cues[0].text.find("world") != std::string::npos);
    CHECK(r.cues[0].styleName == "Default");
}

TEST(ssa_legacy_format) {
    const char* s =
        "[Script Info]\n\n[V4 Styles]\nFormat: Name, Fontname, Fontsize\n"
        "Style: Default,Arial,20\n\n[Events]\n"
        "Dialogue: Marked=0,0:00:01.00,0:00:02.00,Default,,0,0,0,;Hello\n";
    auto r = P(s);
    CHECK_EQ(r.format, Format::Ssa);
    CHECK(!r.cues.empty());
}

TEST(microdvd_frame_conversion) {
    auto r = P("{100}{200}hello\n{300}{400}world\n");
    CHECK_EQ(r.format, Format::MicroDvd);
    CHECK_EQ(r.cues.size(), size_t(2));
    // 100 frames at 25 fps = 4000 ms.
    CHECK_EQ(r.cues[0].startMs, int64_t(4000));
    CHECK(r.cues[0].text == "hello");
}

TEST(microdvd_fps_marker) {
    auto r = P("{1}{1}50.0\n{100}{200}x\n", Format::MicroDvd);
    CHECK_EQ(r.cues.size(), size_t(1));
    // 100 frames at 50 fps = 2000 ms.
    CHECK_EQ(r.cues[0].startMs, int64_t(2000));
}

TEST(sami_sync_parsing) {
    const char* s =
        "<SAMI><BODY><SYNC Start=1000><P>one\n"
        "<SYNC Start=2000><P>two\n</BODY></SAMI>";
    auto r = P(s);
    CHECK_EQ(r.format, Format::Sami);
    CHECK_EQ(r.cues.size(), size_t(2));
    CHECK_EQ(r.cues[0].startMs, int64_t(1000));
    CHECK(r.cues[1].text.find("two") != std::string::npos);
}

TEST(pjs_parsing) {
    auto r = P("100,200,\"hello\"\n200,300,\"world\"\n");
    CHECK_EQ(r.format, Format::Pjs);
    CHECK_EQ(r.cues.size(), size_t(2));
    CHECK_EQ(r.cues[0].startMs, int64_t(1000));  // hundredths
    CHECK(r.cues[0].text == "hello");
}

TEST(sbv_parsing) {
    auto r = P("0:00:01.000,0:00:03.000\nhello there\n\n"
               "0:00:04.000,0:00:05.000\nsecond\n");
    CHECK_EQ(r.format, Format::Sbv);
    CHECK_EQ(r.cues.size(), size_t(2));
    CHECK_EQ(r.cues[0].endMs, int64_t(3000));
}

TEST(lrc_multi_timestamp) {
    auto r = P("[00:10.00][00:20.00]la la la\n[ar:Artist]\n");
    CHECK_EQ(r.format, Format::Lrc);
    CHECK_EQ(r.cues.size(), size_t(2));
    CHECK_EQ(r.cues[0].startMs, int64_t(10000));
    CHECK_EQ(r.cues[1].startMs, int64_t(20000));
    CHECK(r.cues[0].text == "la la la");
}

TEST(mpl2_parsing) {
    auto r = P("[10][20]hello\n");
    CHECK_EQ(r.format, Format::Mpl2);
    CHECK_EQ(r.cues.size(), size_t(1));
    CHECK_EQ(r.cues[0].startMs, int64_t(1000));  // deciseconds
}

TEST(tmp_derives_end_from_next) {
    auto r = P("00:00:01 first\n00:00:05 second\n");
    CHECK_EQ(r.format, Format::Tmp);
    CHECK_EQ(r.cues.size(), size_t(2));
    CHECK_EQ(r.cues[0].startMs, int64_t(1000));
    CHECK_EQ(r.cues[0].endMs, int64_t(5000));
}

TEST(ted_json_captions) {
    const char* s =
        R"({"captions":[{"start":1.0,"duration":2.0,"content":"hi"},
                        {"start":3.5,"duration":1.0,"content":"there"}]})";
    auto r = P(s);
    CHECK_EQ(r.format, Format::TedJson);
    CHECK_EQ(r.cues.size(), size_t(2));
    CHECK_EQ(r.cues[0].startMs, int64_t(1000));
    CHECK_EQ(r.cues[0].endMs, int64_t(3000));
}

TEST(json_bare_array) {
    const char* s = R"([{"startTime":0,"dur":1,"text":"a"}])";
    auto r = P(s);
    CHECK_EQ(r.cues.size(), size_t(1));
}

TEST(empty_and_garbage_inputs) {
    CHECK(parse("").diagnostics.size() >= size_t(1));
    CHECK(parse("   \n  \n").format == Format::Auto);
    auto r = parse("this is not a subtitle at all just prose text");
    CHECK(!r.ok());
    CHECK(r.cues.empty());
}

TEST(utf8_bom_stripped) {
    std::string s = "\xEF\xBB\xBF" "1\n00:00:01,000 --> 00:00:02,000\nhi\n";
    auto r = parse(s);
    CHECK_EQ(r.cues.size(), size_t(1));
    CHECK(r.cues[0].text == "hi");
}

TEST(utf16le_transcoded) {
    // "1\n00:00:01,000 --> ..." encoded UTF-16LE with BOM.
    std::string s;
    s += '\xFF'; s += '\xFE';
    const char* txt = "1\n00:00:01,000 --> 00:00:02,000\nhi\n";
    for (const char* p = txt; *p; ++p) { s.push_back(*p); s.push_back('\0'); }
    auto r = parse(s);
    CHECK_EQ(r.cues.size(), size_t(1));
    CHECK(r.cues[0].text == "hi");
}

RUN_ALL_TESTS()
