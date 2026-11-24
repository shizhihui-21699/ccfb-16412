// SPDX-License-Identifier: MIT
// The remaining block/line-oriented formats: MicroDVD, SAMI, PJS, TED JSON,
// SBV, LRC, MPL2 and TMP. Each reuses the same bounded primitives, so their
// format-specific code is only about locating timestamps and text.
#include "internal/parsers.h"

#include <array>

namespace subsafe::detail {

// Default cue duration (ms) for formats that only give a start time, and the
// cap applied to any derived end time.
static constexpr int64_t kDefaultDurationMs = 3000;

// ---------------------------------------------------------------------------
// MicroDVD: {frame1}{frame2}text   with an optional first-line FPS marker.
// ---------------------------------------------------------------------------
void parseMicroDvd(ParseContext& ctx, std::string_view raw) {
    BoundedReader rd(raw, ctx.lim, ctx.diag);
    std::string_view line;
    double fps = 25.0;

    while (rd.nextLine(line)) {
        size_t ln = rd.lineNumber();
        std::string_view t = trim(line);
        if (t.empty()) continue;

        auto readBrace = [&](size_t pos, uint64_t& frame, size_t& next) {
            if (pos >= t.size() || t[pos] != '{') return false;
            size_t c = t.find('}', pos + 1);
            if (c == std::string_view::npos) return false;
            if (!parseUint64(trim(t.substr(pos + 1, c - pos - 1)), frame))
                return false;
            next = c + 1;
            return true;
        };

        uint64_t f1 = 0, f2 = 0;
        size_t p1 = 0, p2 = 0;
        if (!readBrace(0, f1, p1) || !readBrace(p1, f2, p2)) {
            ctx.diag.warning(ln, "microdvd.bad_frame", "line dropped");
            continue;
        }

        // FPS definition line: {n}{n}23.976
        if (f1 == f2 && p2 < t.size()) {
            double declared = 0.0;
            if (parseBoundedDouble(trim(t.substr(p2)), declared, 1000.0) &&
                declared > 0.0) {
                fps = declared;
                continue;
            }
        }

        Cue cue;
        if (!framesToMs(f1, fps, cue.startMs) ||
            !framesToMs(f2, fps, cue.endMs)) {
            ctx.diag.warning(ln, "microdvd.time_overflow", "line dropped");
            continue;
        }
        std::string text(t.substr(p2));
        for (char& c : text) if (c == '|') c = '\n';   // line separator
        cue.text = std::move(text);
        finishCueText(ctx, cue, InlineTagMode::HtmlInline, nullptr);
        normalizeRange(ctx, ln, cue);
        if (!cue.empty()) ctx.addCue(std::move(cue));
    }
}

// ---------------------------------------------------------------------------
// SAMI (.smi): HTML/SGML hybrid driven by <SYNC Start=ms> ... <P ...>text.
// Parsed with a tolerant single-pass line scanner; all markup is sandboxed
// during finishCueText. A SYNC tag closes the previous cue.
// ---------------------------------------------------------------------------
namespace {

// Case-insensitive search for "<SYNC" within s. Returns position or npos.
size_t findSync(std::string_view s) noexcept {
    for (size_t i = 0; i + 5 <= s.size(); ++i) {
        if (s[i] != '<') continue;
        char a = s[i + 1], b = s[i + 2], c = s[i + 3], d = s[i + 4];
        auto lo = [](char x) { return (x >= 'a' && x <= 'z') ? char(x - 32) : x; };
        if (lo(a) == 'S' && lo(b) == 'Y' && lo(c) == 'N' && lo(d) == 'C')
            return i;
    }
    return std::string_view::npos;
}

// Parse the Start= value out of a "<SYNC ...>" tag; false if malformed.
// Only the leading integer is consumed, so trailing attributes/whitespace
// cannot make parseInt64 reject an otherwise valid timestamp.
bool syncStart(std::string_view tag, int64_t& outMs) noexcept {
    size_t eq = tag.find('=');
    if (eq == std::string_view::npos) return false;
    std::string_view val = trim(tag.substr(eq + 1));
    size_t n = 0;
    while (n < val.size() && val[n] >= '0' && val[n] <= '9') ++n;
    if (n == 0) return false;
    if (!parseInt64(val.substr(0, n), outMs)) return false;
    return outMs >= 0;
}

} // namespace

void parseSami(ParseContext& ctx, std::string_view raw) {
    BoundedReader rd(raw, ctx.lim, ctx.diag);
    std::string_view line;
    Cue cue;
    bool have = false;

    auto flush = [&](size_t ln) {
        if (!have) return;
        // SAMI supplies only start times. A zero end would otherwise be read
        // as a reversed range and swapped, so assign a bounded default.
        if (cue.endMs <= cue.startMs)
            cue.endMs = clampTime(cue.startMs + kDefaultDurationMs, ctx.lim);
        finishCueText(ctx, cue, InlineTagMode::HtmlInline, nullptr);
        normalizeRange(ctx, ln, cue);
        if (!cue.empty()) ctx.addCue(std::move(cue));
        cue = Cue{};
        have = false;
    };

    while (rd.nextLine(line)) {
        size_t ln = rd.lineNumber();
        std::string_view rest = line;

        // A physical line can hold several SYNC tags; process each in turn.
        while (true) {
            size_t pos = findSync(rest);
            if (pos == std::string_view::npos) {
                // Plain continuation text belonging to the open cue.
                if (have && !trim(rest).empty())
                    appendCueLine(ctx, cue.text, rest);
                break;
            }

            // Text preceding this SYNC belongs to the previous cue.
            if (pos > 0 && have && !trim(rest.substr(0, pos)).empty())
                appendCueLine(ctx, cue.text, rest.substr(0, pos));

            size_t gt = rest.find('>', pos);
            if (gt == std::string_view::npos) {
                ctx.diag.warning(ln, "sami.bad_sync", "unterminated SYNC tag");
                flush(ln);
                rest = {};
                break;
            }
            std::string_view tag = rest.substr(pos, gt - pos + 1);
            flush(ln);   // previous cue ends where the new SYNC begins

            int64_t startMs = 0;
            if (!syncStart(tag, startMs)) {
                ctx.diag.warning(ln, "sami.bad_start",
                                 "SYNC without valid Start; skipped");
                rest = rest.substr(gt + 1);
                continue;
            }
            cue.startMs = clampTime(startMs, ctx.lim);
            have = true;
            rest = rest.substr(gt + 1);
        }
    }
    flush(rd.lineNumber());
}

// ---------------------------------------------------------------------------
// PJS (.psb): start,end,"text"   with times in hundredths of a second.
// ---------------------------------------------------------------------------
void parsePjs(ParseContext& ctx, std::string_view raw) {
    BoundedReader rd(raw, ctx.lim, ctx.diag);
    std::string_view line;
    while (rd.nextLine(line)) {
        size_t ln = rd.lineNumber();
        std::string_view t = trim(line);
        if (t.empty()) continue;
        std::string_view f[4];
        size_t n = splitView(t, ',', f, 4);
        if (n < 3) { ctx.diag.warning(ln, "pjs.bad_line", "dropped"); continue; }
        int64_t a = 0, b = 0;
        if (!parseInt64(trim(f[0]), a) || !parseInt64(trim(f[1]), b) ||
            a < 0 || b < 0) {
            ctx.diag.warning(ln, "pjs.bad_time", "dropped");
            continue;
        }
        Cue cue;
        cue.startMs = clampTime(a * 10, ctx.lim);
        cue.endMs   = clampTime(b * 10, ctx.lim);
        // Rejoin the quoted text (commas may appear inside it).
        std::string text(f[2].data(), f[2].size());
        for (size_t k = 3; k < n; ++k) { text.push_back(','); text += f[k]; }
        if (!text.empty() && text.front() == '"') text.erase(text.begin());
        if (!text.empty() && text.back() == '"') text.pop_back();
        cue.text = std::move(text);
        finishCueText(ctx, cue, InlineTagMode::Plain, nullptr);
        normalizeRange(ctx, ln, cue);
        if (!cue.empty()) ctx.addCue(std::move(cue));
    }
}

// ---------------------------------------------------------------------------
// SBV (YouTube): H:MM:SS.mmm,H:MM:SS.mmm  then text until blank line.
// ---------------------------------------------------------------------------
void parseSbv(ParseContext& ctx, std::string_view raw) {
    BoundedReader rd(raw, ctx.lim, ctx.diag);
    std::string_view line;
    Cue cue;
    bool have = false;

    auto flush = [&](size_t ln) {
        if (!have) return;
        finishCueText(ctx, cue, InlineTagMode::Plain, nullptr);
        normalizeRange(ctx, ln, cue);
        if (!cue.empty()) ctx.addCue(std::move(cue));
        cue = Cue{};
        have = false;
    };

    while (rd.nextLine(line)) {
        size_t ln = rd.lineNumber();
        std::string_view t = trim(line);
        if (t.empty()) { flush(ln); continue; }
        if (!have) {
            size_t comma = t.find(',');
            if (comma == std::string_view::npos) {
                ctx.diag.warning(ln, "sbv.bad_header", "dropped");
                continue;
            }
            Cue c;
            if (!parseHmsMs(ctx, ln, t.substr(0, comma), c.startMs) ||
                !parseHmsMs(ctx, ln, t.substr(comma + 1), c.endMs)) {
                ctx.diag.warning(ln, "sbv.bad_time", "dropped");
                continue;
            }
            cue = std::move(c);
            have = true;
        } else {
            appendCueLine(ctx, cue.text, t);
        }
    }
    flush(rd.lineNumber());
}

// ---------------------------------------------------------------------------
// LRC lyrics: [mm:ss.xx] text, multiple bracketed timestamps allowed.
// ---------------------------------------------------------------------------
void parseLrc(ParseContext& ctx, std::string_view raw) {
    BoundedReader rd(raw, ctx.lim, ctx.diag);
    std::string_view line;
    while (rd.nextLine(line)) {
        size_t ln = rd.lineNumber();
        std::string_view t = trim(line);
        if (t.empty() || t.front() != '[') continue;

        std::vector<int64_t> stamps;
        size_t pos = 0;
        while (pos < t.size() && t[pos] == '[') {
            size_t c = t.find(']', pos + 1);
            if (c == std::string_view::npos) break;
            int64_t ms = 0;
            if (parseHmsMs(ctx, ln, t.substr(pos + 1, c - pos - 1), ms))
                stamps.push_back(ms);
            pos = c + 1;
        }
        if (stamps.empty()) continue;   // metadata tags [ar:...] etc.

        std::string text(t.substr(pos));
        for (int64_t start : stamps) {
            Cue cue;
            cue.startMs = clampTime(start, ctx.lim);
            cue.endMs = clampTime(start + kDefaultDurationMs, ctx.lim);
            cue.text = text;
            finishCueText(ctx, cue, InlineTagMode::Plain, nullptr);
            normalizeRange(ctx, ln, cue);
            if (!cue.empty()) ctx.addCue(std::move(cue));
        }
    }
}

// ---------------------------------------------------------------------------
// MPL2: [startDecisec][endDecisec] text
// ---------------------------------------------------------------------------
void parseMpl2(ParseContext& ctx, std::string_view raw) {
    BoundedReader rd(raw, ctx.lim, ctx.diag);
    std::string_view line;
    while (rd.nextLine(line)) {
        size_t ln = rd.lineNumber();
        std::string_view t = trim(line);
        if (t.size() < 2 || t.front() != '[') continue;
        size_t c1 = t.find(']', 1);
        if (c1 == std::string_view::npos || c1 + 1 >= t.size() ||
            t[c1 + 1] != '[') {
            ctx.diag.warning(ln, "mpl2.bad_line", "dropped");
            continue;
        }
        size_t c2 = t.find(']', c1 + 2);
        if (c2 == std::string_view::npos) {
            ctx.diag.warning(ln, "mpl2.bad_line", "dropped");
            continue;
        }
        int64_t a = 0, b = 0;
        if (!parseInt64(trim(t.substr(1, c1 - 1)), a) ||
            !parseInt64(trim(t.substr(c1 + 2, c2 - c1 - 2)), b) ||
            a < 0 || b < 0) {
            ctx.diag.warning(ln, "mpl2.bad_time", "dropped");
            continue;
        }
        Cue cue;
        cue.startMs = clampTime(a * 100, ctx.lim);
        cue.endMs   = clampTime(b * 100, ctx.lim);
        cue.text = std::string(t.substr(c2 + 1));
        finishCueText(ctx, cue, InlineTagMode::HtmlInline, nullptr);
        normalizeRange(ctx, ln, cue);
        if (!cue.empty()) ctx.addCue(std::move(cue));
    }
}

// ---------------------------------------------------------------------------
// TMP: HH:MM:SS text  (single timestamp; end derived from the next cue)
// ---------------------------------------------------------------------------
void parseTmp(ParseContext& ctx, std::string_view raw) {
    BoundedReader rd(raw, ctx.lim, ctx.diag);
    std::string_view line;
    std::vector<Cue> staged;

    while (rd.nextLine(line)) {
        size_t ln = rd.lineNumber();
        std::string_view t = trim(line);
        if (t.size() < 8 || t[2] != ':' || t[5] != ':') continue;
        int64_t ms = 0;
        if (!parseHmsMs(ctx, ln, t.substr(0, 8), ms)) continue;
        Cue cue;
        cue.startMs = clampTime(ms, ctx.lim);
        cue.text = std::string(t.substr(8));
        finishCueText(ctx, cue, InlineTagMode::Plain, nullptr);
        if (!cue.empty()) staged.push_back(std::move(cue));
        if (staged.size() > ctx.lim.maxCues) break;
    }
    // Derive end times from following starts, with a bounded default tail.
    for (size_t i = 0; i < staged.size(); ++i) {
        int64_t end = (i + 1 < staged.size())
                          ? staged[i + 1].startMs
                          : clampTime(staged[i].startMs + kDefaultDurationMs,
                                      ctx.lim);
        staged[i].endMs = end;
        normalizeRange(ctx, 0, staged[i]);
        ctx.addCue(std::move(staged[i]));
    }
}

} // namespace subsafe::detail
