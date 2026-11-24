// SPDX-License-Identifier: MIT
#include "internal/common.h"

#include <algorithm>
#include <cerrno>
#include <cfloat>
#include <cstring>

namespace subsafe::detail {

// ---------------------------------------------------------------------------
// DiagSink
// ---------------------------------------------------------------------------
void DiagSink::report(Severity sev, size_t line, std::string_view code,
                      std::string_view msg) {
    if (res_.diagnostics.size() < lim_.maxStoredDiagnostics) {
        Diagnostic d;
        d.severity = sev;
        d.line = line;
        d.code.assign(code.data(), code.size());
        // Defensive: never let a diagnostic string itself carry huge input.
        d.message.assign(msg.data(), std::min(msg.size(), size_t(512)));
        res_.diagnostics.push_back(std::move(d));
    } else {
        ++res_.suppressedDiagnostics;
    }
}

// ---------------------------------------------------------------------------
// BoundedReader
// ---------------------------------------------------------------------------
BoundedReader::BoundedReader(std::string_view raw, const ParserLimits& lim,
                             DiagSink& diag)
    : raw_(raw), lim_(lim), diag_(diag) {
    if (raw_.size() > lim_.maxInputBytes) {
        diag_.fatal("input.too_large",
                    "subtitle exceeds maxInputBytes; refused before decode");
        throw FatalAbort("input.too_large");
    }
    decode();
    view_ = decoded_.empty() ? raw_ : std::string_view(decoded_);
}

namespace {

// Decode one UTF-16 code unit stream (with surrogate pairing) into UTF-8.
// Output is hard-capped; on overflow the remainder is dropped and reported.
void transcodeUtf16(std::string_view in, bool bigEndian, bool hasBom,
                    std::string& out, const ParserLimits& lim,
                    DiagSink& diag) {
    const size_t units = in.size() / 2;
    out.reserve(std::min(in.size(), lim.maxInputBytes));
    bool truncated = false;

    auto u16at = [&](size_t i) -> uint16_t {
        uint8_t a = static_cast<uint8_t>(in[2 * i]);
        uint8_t b = static_cast<uint8_t>(in[2 * i + 1]);
        return bigEndian ? uint16_t((a << 8) | b) : uint16_t((b << 8) | a);
    };
    auto push = [&](uint32_t cp) {
        char buf[4];
        int n;
        if (cp < 0x80) { buf[0] = char(cp); n = 1; }
        else if (cp < 0x800) {
            buf[0] = char(0xC0 | (cp >> 6));
            buf[1] = char(0x80 | (cp & 0x3F)); n = 2;
        } else if (cp < 0x10000) {
            buf[0] = char(0xE0 | (cp >> 12));
            buf[1] = char(0x80 | ((cp >> 6) & 0x3F));
            buf[2] = char(0x80 | (cp & 0x3F)); n = 3;
        } else {
            buf[0] = char(0xF0 | (cp >> 18));
            buf[1] = char(0x80 | ((cp >> 12) & 0x3F));
            buf[2] = char(0x80 | ((cp >> 6) & 0x3F));
            buf[3] = char(0x80 | (cp & 0x3F)); n = 4;
        }
        if (out.size() + static_cast<size_t>(n) > lim.maxInputBytes) {
            truncated = true;
            return;
        }
        out.append(buf, static_cast<size_t>(n));
    };

    for (size_t i = 0; i < units; ++i) {
        uint32_t cu = u16at(i);
        if (cu >= 0xD800 && cu <= 0xDBFF) {          // high surrogate
            if (i + 1 < units) {
                uint32_t lo = u16at(i + 1);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    uint32_t cp = 0x10000 + ((cu - 0xD800) << 10)
                                          + (lo - 0xDC00);
                    push(cp);
                    ++i;
                    continue;
                }
            }
            push(0xFFFD);                            // unpaired high
        } else if (cu >= 0xDC00 && cu <= 0xDFFF) {
            push(0xFFFD);                            // unpaired low
        } else {
            push(cu);
        }
        if (truncated) break;
    }
    (void)hasBom;
    if (truncated) {
        diag.warning(0, "encode.truncated",
                     "transcoded subtitle hit maxInputBytes; tail dropped");
    }
}

} // namespace

void BoundedReader::decode() {
    static constexpr unsigned char BOM8[3] = {0xEF, 0xBB, 0xBF};
    if (raw_.size() >= 3 &&
        static_cast<unsigned char>(raw_[0]) == BOM8[0] &&
        static_cast<unsigned char>(raw_[1]) == BOM8[1] &&
        static_cast<unsigned char>(raw_[2]) == BOM8[2]) {
        raw_.remove_prefix(3);
        return;
    }
    if (raw_.size() >= 2) {
        unsigned char a = static_cast<unsigned char>(raw_[0]);
        unsigned char b = static_cast<unsigned char>(raw_[1]);
        if (a == 0xFF && b == 0xFE) {                // UTF-16 LE
            transcoded_ = true;
            transcodeUtf16(raw_.substr(2), false, true, decoded_, lim_, diag_);
            return;
        }
        if (a == 0xFE && b == 0xFF) {                // UTF-16 BE
            transcoded_ = true;
            transcodeUtf16(raw_.substr(2), true, true, decoded_, lim_, diag_);
            return;
        }
        // BOM-less heuristic: an alternating NUL pattern in the head.
        size_t probe = std::min<size_t>(raw_.size(), 256);
        if (probe >= 4) {
            size_t zeros = 0;
            for (size_t i = 0; i < probe; ++i)
                if (raw_[i] == '\0') ++zeros;
            if (zeros >= probe / 4) {
                bool le = (raw_[1] == '\0' && raw_[3] == '\0');
                bool be = (raw_[0] == '\0' && raw_[2] == '\0');
                if (le || be) {
                    transcoded_ = true;
                    transcodeUtf16(raw_, be, false, decoded_, lim_, diag_);
                    diag_.warning(0, "encode.guessed_utf16",
                                  "no BOM; decoded as UTF-16 by heuristic");
                }
            }
        }
    }
}

bool BoundedReader::nextLine(std::string_view& out) noexcept {
    if (pos_ >= view_.size()) return false;
    if (lineNo_ >= lim_.maxLines) {
        if (!lineBudgetReported_) {
            diag_.error(0, "input.line_limit",
                        "maxLines reached; remaining input not scanned");
            lineBudgetReported_ = true;
        }
        return false;
    }
    size_t nl = view_.find('\n', pos_);
    size_t end = (nl == std::string_view::npos) ? view_.size() : nl;
    out = view_.substr(pos_, end - pos_);
    if (!out.empty() && out.back() == '\r') out.remove_suffix(1);
    pos_ = (nl == std::string_view::npos) ? view_.size() : nl + 1;
    ++lineNo_;
    return true;
}

// ---------------------------------------------------------------------------
// ParseContext helpers
// ---------------------------------------------------------------------------
bool ParseContext::appendCapped(std::string& dst, std::string_view src,
                                size_t fieldCap) {
    if (src.empty()) return true;
    size_t roomField = (dst.size() >= fieldCap) ? 0 : fieldCap - dst.size();
    size_t n = std::min(src.size(), roomField);

    size_t roomBudget = budget.remaining();
    bool budgetHit = false;
    if (n > roomBudget) {
        n = roomBudget;
        budgetHit = true;
    }
    if (n > 0) {
        dst.append(src.data(), n);
        budget.take(n);
    }
    if (n < src.size()) {
        markLimit();
        if (budgetHit)
            diag.warning(0, "budget.text_exhausted",
                         "global text budget reached; content truncated");
        else
            diag.warning(0, "field.too_long",
                         "field exceeded its per-field cap; truncated");
        return false;
    }
    return true;
}

bool ParseContext::addCue(Cue cue) {
    if (result.cues.size() >= lim.maxCues) {
        if (result.droppedCues == 0)
            diag.warning(0, "cue.limit", "maxCues reached; further cues dropped");
        ++result.droppedCues;
        markLimit();
        return false;
    }
    result.cues.push_back(std::move(cue));
    return true;
}

// ---------------------------------------------------------------------------
// Integer parsing
// ---------------------------------------------------------------------------
bool parseUint64(std::string_view s, uint64_t& out) noexcept {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    if (i == s.size()) return false;
    uint64_t acc = 0;
    bool any = false;
    for (; i < s.size(); ++i) {
        char c = s[i];
        if (c < '0' || c > '9') {
            while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
            if (i != s.size()) return false;   // junk after digits
            break;
        }
        any = true;
        uint64_t d = static_cast<uint64_t>(c - '0');
        if (acc > (UINT64_MAX - d) / 10) return false;
        acc = acc * 10 + d;
    }
    if (!any) return false;
    out = acc;
    return true;
}

bool parseInt64(std::string_view s, int64_t& out) noexcept {
    size_t i = 0;
    bool neg = false;
    if (i < s.size() && (s[i] == '-' || s[i] == '+')) {
        neg = (s[i] == '-');
        ++i;
    }
    uint64_t mag = 0;
    if (!parseUint64(s.substr(i), mag)) return false;
    uint64_t limit = neg ? (uint64_t(INT64_MAX) + 1) : uint64_t(INT64_MAX);
    if (mag > limit) return false;
    out = neg ? -static_cast<int64_t>(mag) : static_cast<int64_t>(mag);
    return true;
}

bool parseBoundedDouble(std::string_view s, double& out,
                        double absMax) noexcept {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    int sign = 1;
    if (i < s.size() && (s[i] == '-' || s[i] == '+')) {
        if (s[i] == '-') sign = -1;
        ++i;
    }
    uint64_t whole = 0;
    bool any = false;
    unsigned digits = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        any = true;
        if (++digits <= 18) {
            whole = whole * 10 + static_cast<uint64_t>(s[i] - '0');
        }
        ++i;
    }
    uint64_t frac = 0;
    unsigned fracDigits = 0;
    if (i < s.size() && s[i] == '.') {
        ++i;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            any = true;
            if (fracDigits < 18) {
                frac = frac * 10 + static_cast<uint64_t>(s[i] - '0');
                ++fracDigits;
            }
            ++digits;
            ++i;
        }
    }
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    if (!any || i != s.size() || digits > 300) return false;  // rejects e/E, nan, inf

    double scale = 1.0;
    for (unsigned k = 0; k < fracDigits; ++k) scale *= 10.0;
    double v = sign * (static_cast<double>(whole) +
                       static_cast<double>(frac) / scale);
    if (!(v == v) || v > absMax || v < -absMax) return false;
    out = v;
    return true;
}

// ---------------------------------------------------------------------------
// Time parsing
// ---------------------------------------------------------------------------
int64_t clampTime(int64_t ms, const ParserLimits& lim) noexcept {
    if (ms < 0) return 0;
    if (ms > lim.maxTimestampMs) return lim.maxTimestampMs;
    return ms;
}

int32_t clampInt(int64_t v, int32_t lo, int32_t hi) noexcept {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return static_cast<int32_t>(v);
}

bool parseHmsMs(ParseContext& ctx, size_t lineNo, std::string_view s,
                int64_t& outMs) noexcept {
    std::string_view parts[3];
    size_t n = splitView(s, ':', parts, 3);
    if (n < 2 || n > 3) return false;

    int64_t hour = 0, minute = 0;
    int64_t wholeSec = 0;
    int64_t fracMs = 0;

    for (size_t i = 0; i < n; ++i) {
        std::string_view tok = trim(parts[i]);
        if (tok.empty()) return false;

        if (i != n - 1) {
            // Pure integer hour/minute components.
            int64_t v = 0;
            if (!parseInt64(tok, v) || v < 0) return false;
            if (i == 0) {
                if (v > 99) return false;
                hour = v;
            } else {
                if (v > 59) {
                    ctx.diag.warning(lineNo, "time.field_overflow",
                                     "minutes > 59 clamped to 59");
                    v = 59;
                }
                minute = v;
            }
            continue;
        }

        // Final component: whole seconds plus an optional fraction.
        size_t dot = tok.find_first_of(".,");
        std::string_view wholeTok = (dot == std::string_view::npos)
                                        ? tok : tok.substr(0, dot);
        if (!parseInt64(wholeTok, wholeSec) || wholeSec < 0) return false;
        if (wholeSec > 59) {
            ctx.diag.warning(lineNo, "time.field_overflow",
                             "seconds > 59 clamped to 59");
            wholeSec = 59;
        }
        if (dot != std::string_view::npos) {
            std::string_view fs = tok.substr(dot + 1);
            unsigned frac = 0;
            unsigned cnt = 0;
            for (char c : fs) {
                if (c < '0' || c > '9') return false;
                if (cnt < 3) { frac = frac * 10 + unsigned(c - '0'); ++cnt; }
                // Extra precision is discarded, never used as a count.
            }
            while (cnt < 3) { frac *= 10; ++cnt; }
            fracMs = frac;
        }
        if (n == 2) hour = 0;
    }

    // Overflow-checked accumulation; no component can be huge here.
    __int128 total = __int128(hour) * 3600000 +
                     __int128(minute) * 60000 +
                     __int128(wholeSec) * 1000 +
                     __int128(fracMs);
    if (total < 0 || total > __int128(INT64_MAX)) return false;
    int64_t ms = int64_t(total);
    if (ms > ctx.lim.maxTimestampMs) {
        ctx.diag.warning(lineNo, "time.range",
                         "timestamp beyond maxTimestampMs; clamped");
        ms = ctx.lim.maxTimestampMs;
    }
    outMs = ms;
    return true;
}

bool framesToMs(uint64_t frame, double fps, int64_t& outMs) noexcept {
    if (!(fps == fps) || fps <= 0.0 || fps > 1000.0) return false;
    // frame * 1000 must stay inside int64.
    if (frame > uint64_t(INT64_MAX) / 1000) return false;
    double ms = (static_cast<double>(frame) / fps) * 1000.0;
    if (!(ms == ms) || ms < 0.0 || ms > static_cast<double>(INT64_MAX))
        return false;
    outMs = static_cast<int64_t>(ms);
    return true;
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------
std::string_view trim(std::string_view s) noexcept {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' ||
                     s[b] == '\n' || s[b] == '\f' || s[b] == '\v'))
        ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' ||
                     s[e - 1] == '\r' || s[e - 1] == '\n' ||
                     s[e - 1] == '\f' || s[e - 1] == '\v'))
        --e;
    return s.substr(b, e - b);
}

bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'a' && x <= 'z') x = char(x - 'a' + 'A');
        if (y >= 'a' && y <= 'z') y = char(y - 'a' + 'A');
        if (x != y) return false;
    }
    return true;
}

bool istartsWith(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size() &&
           iequals(s.substr(0, prefix.size()), prefix);
}

bool iendsWith(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size() &&
           iequals(s.substr(s.size() - suffix.size()), suffix);
}

size_t splitView(std::string_view s, char delim, std::string_view* out,
                 size_t maxParts) noexcept {
    if (maxParts == 0) return 0;
    size_t count = 0;
    size_t start = 0;
    for (size_t i = 0; i < s.size() && count + 1 < maxParts; ++i) {
        if (s[i] == delim) {
            out[count++] = s.substr(start, i - start);
            start = i + 1;
        }
    }
    out[count++] = s.substr(start);
    return count;
}

bool assignCapped(ParseContext& ctx, std::string& dst,
                  std::string_view src, size_t fieldCap) {
    dst.clear();
    return ctx.appendCapped(dst, src, fieldCap);
}

// ---------------------------------------------------------------------------
// UTF-8 validation / repair
// ---------------------------------------------------------------------------
std::string sanitizeUtf8(ParseContext& ctx, std::string_view s) {
    std::string out;
    size_t i = 0;
    auto emitReplacement = [&] {
        static constexpr char rep[3] = {char(0xEF), char(0xBF), char(0xBD)};
        ctx.appendCapped(out, std::string_view(rep, 3),
                         ctx.lim.maxCueTextBytes);
    };
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        uint32_t cp = 0;
        size_t len = 0;
        if (c < 0x80) { cp = c; len = 1; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
        else { emitReplacement(); ++i; continue; }

        if (i + len > s.size()) { emitReplacement(); break; }
        bool valid = (len == 1);
        for (size_t k = 1; k < len; ++k) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) { valid = false; break; }
            cp = (cp << 6) | (cc & 0x3F);
        }
        // Reject overlongs, surrogates and out-of-range code points.
        if (valid) {
            uint32_t minCp = len == 1 ? 0 : len == 2 ? 0x80 :
                             len == 3 ? 0x800 : 0x10000;
            if (cp < minCp || cp > 0x10FFFF ||
                (cp >= 0xD800 && cp <= 0xDFFF) || cp == 0)
                valid = false;
        }
        if (!valid) {
            emitReplacement();
            ++i;
            continue;
        }
        ctx.appendCapped(out, s.substr(i, len), ctx.lim.maxCueTextBytes);
        i += len;
    }
    return out;
}

bool appendCueLine(ParseContext& ctx, std::string& text,
                   std::string_view line) {
    if (!text.empty()) {
        if (!ctx.appendCapped(text, std::string_view("\n", 1),
                              ctx.lim.maxCueTextBytes))
            return false;
    }
    return ctx.appendCapped(text, line, ctx.lim.maxCueTextBytes);
}

} // namespace subsafe::detail
