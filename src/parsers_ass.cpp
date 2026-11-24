// SPDX-License-Identifier: MIT
// Advanced SubStation Alpha (.ass) and legacy SubStation Alpha v4 (.ssa).
//
// This is the historically most dangerous format for this codebase: style
// definitions can be megabytes long, [Fonts] sections carry binary blobs,
// and the override language drives renderer allocation. The parser therefore:
//   * tracks the current [Section] and refuses to confuse font bytes with
//     dialogue,
//   * bounds every field and every container,
//   * hands style names / dialogue text through the StylePolicy sandbox,
//   * decodes embedded fonts only when the policy allows it and caps them.
#include "internal/parsers.h"

#include <array>

namespace subsafe::detail {

namespace {

// ASS timestamp: H:MM:SS.cc (centiseconds). SSA v4 uses the same shape.
bool parseAssTime(ParseContext& ctx, size_t lineNo, std::string_view s,
                  int64_t& outMs) {
    s = trim(s);
    std::string_view parts[3];
    size_t n = splitView(s, ':', parts, 3);
    if (n < 2 || n > 3) return false;

    int64_t hour = 0, minute = 0;
    if (n == 3) {
        if (!parseInt64(trim(parts[0]), hour) || hour < 0 || hour > 99)
            return false;
        if (!parseInt64(trim(parts[1]), minute) || minute < 0) return false;
        if (minute > 59) { minute = 59; ctx.diag.warning(lineNo,
            "time.field_overflow", "minutes > 59 clamped"); }
    } else {
        if (!parseInt64(trim(parts[0]), minute) || minute < 0) return false;
        if (minute > 59) { minute = 59; ctx.diag.warning(lineNo,
            "time.field_overflow", "minutes > 59 clamped"); }
    }

    std::string_view last = trim(parts[n - 1]);
    size_t dot = last.find('.');
    if (dot == std::string_view::npos) dot = last.find(',');
    int64_t sec = 0;
    int64_t centi = 0;
    if (dot == std::string_view::npos) {
        if (!parseInt64(last, sec) || sec < 0) return false;
    } else {
        if (!parseInt64(last.substr(0, dot), sec) || sec < 0) return false;
        std::string_view frac = last.substr(dot + 1);
        if (frac.size() != 2) {
            // Malformed centiseconds: tolerate 1 or 3 digits, reject junk.
            if (frac.empty() || frac.size() > 3) return false;
            int64_t f = 0;
            if (!parseInt64(frac, f) || f < 0) return false;
            centi = (frac.size() == 1) ? f * 10 : f / 10;
        } else {
            if (!parseInt64(frac, centi) || centi < 0 || centi > 99)
                return false;
        }
    }
    if (sec > 59) { sec = 59; ctx.diag.warning(lineNo,
        "time.field_overflow", "seconds > 59 clamped"); }

    __int128 total = __int128(hour) * 3600000 + __int128(minute) * 60000 +
                     __int128(sec) * 1000 + __int128(centi) * 10;
    if (total < 0 || total > __int128(INT64_MAX)) return false;
    int64_t ms = int64_t(total);
    if (ms > ctx.lim.maxTimestampMs) {
        ms = ctx.lim.maxTimestampMs;
        ctx.diag.warning(lineNo, "time.range", "timestamp clamped");
    }
    outMs = ms;
    return true;
}

// Decode one hex nibble; -1 on invalid.
int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

void parseAss(ParseContext& ctx, std::string_view raw, bool legacySsa) {
    BoundedReader rd(raw, ctx.lim, ctx.diag);
    std::string_view line;

    enum class Section { None, ScriptInfo, Styles, Events, Fonts, Graphics, Other };
    Section section = Section::None;

    size_t styleCount = 0;
    size_t fontCount = 0;
    size_t fontTotal = 0;
    FontData* currentFont = nullptr;

    // Event field layout discovered from the [Events] Format line.
    std::array<int, 12> eventIndex{};
    eventIndex.fill(-1);
    bool haveEventFormat = false;

    auto sectionFromHeader = [&](std::string_view h) -> Section {
        if (h == "Script Info" || h == "ScriptInfo") return Section::ScriptInfo;
        if (h == "V4+ Styles" || h == "V4 Styles" || h == "Styles")
            return Section::Styles;
        if (h == "Events") return Section::Events;
        if (h == "Fonts") return Section::Fonts;
        if (h == "Graphics") return Section::Graphics;
        return Section::Other;
    };

    while (rd.nextLine(line)) {
        size_t ln = rd.lineNumber();
        std::string_view t = trim(line);
        if (t.empty() || t[0] == ';') continue;   // comments / blanks

        // Section header.
        if (t.front() == '[' && t.back() == ']') {
            section = sectionFromHeader(trim(t.substr(1, t.size() - 2)));
            currentFont = nullptr;
            continue;
        }

        size_t colon = t.find(':');
        if (colon == std::string_view::npos) {
            // Inside [Fonts], continuation lines carry base64 without a colon.
            if (section == Section::Fonts && currentFont &&
                ctx.policy.allowEmbeddedFonts) {
                // Feed base64-ish content through the capped font buffer.
                std::vector<uint8_t> tmp;
                tmp.reserve(t.size() / 2 + 1);
                uint32_t accum = 0;
                int bits = 0;
                for (char c : t) {
                    int v = hexNibble(c);
                    // ASS fonts are often raw lines; accept base64 alphabet.
                    int b64 = -1;
                    if (c >= 'A' && c <= 'Z') b64 = c - 'A';
                    else if (c >= 'a' && c <= 'z') b64 = c - 'a' + 26;
                    else if (c >= '0' && c <= '9') b64 = c - '0' + 52;
                    else if (c == '+') b64 = 62;
                    else if (c == '/') b64 = 63;
                    else if (c == '=') continue;
                    (void)v;
                    if (b64 < 0) continue;
                    accum = (accum << 6) | uint32_t(b64);
                    bits += 6;
                    if (bits >= 8) {
                        bits -= 8;
                        tmp.push_back(uint8_t((accum >> bits) & 0xFF));
                        accum &= (1u << bits) - 1;
                    }
                }
                if (fontTotal + tmp.size() > ctx.lim.maxFontTotalBytes) {
                    ctx.diag.warning(ln, "font.total_budget",
                                     "embedded font total budget reached");
                    ctx.markLimit();
                    currentFont = nullptr;
                    continue;
                }
                fontTotal += tmp.size();
                if (!currentFont->append(tmp.data(), tmp.size(),
                                         ctx.lim.maxFontBytes)) {
                    ctx.diag.warning(ln, "font.too_large",
                                     "single embedded font capped");
                    ctx.markLimit();
                }
            }
            continue;
        }

        std::string_view key = trim(t.substr(0, colon));
        std::string_view value = trim(t.substr(colon + 1));

        // ---- [Events] Format: learn field positions once ------------------
        if (section == Section::Events && iequals(key, "Format")) {
            std::string_view fields[16];
            size_t nf = splitView(value, ',', fields, 16);
            struct Map { const char* name; int slot; };
            static const Map map[] = {
                {"Layer", 0}, {"Start", 1}, {"End", 2}, {"Style", 3},
                {"Name", 4}, {"MarginL", 5}, {"MarginR", 6}, {"MarginV", 7},
                {"Effect", 8}, {"Text", 9},
                {"Marked", 10}, {"Style", 3},
            };
            for (size_t f = 0; f < nf; ++f) {
                std::string_view fn = trim(fields[f]);
                for (const Map& m : map)
                    if (iequals(fn, m.name)) {
                        eventIndex[static_cast<size_t>(m.slot)] = int(f);
                        break;
                    }
            }
            haveEventFormat = true;
            continue;
        }

        // ---- [Styles]: count and bound, never store unbounded -------------
        if (section == Section::Styles) {
            if (iequals(key, "Format") || iequals(key, "Style")) {
                if (iequals(key, "Style")) {
                    if (styleCount >= ctx.lim.maxStyles) {
                        ctx.diag.warning(ln, "style.limit",
                                         "maxStyles reached; style dropped");
                        ctx.markLimit();
                    } else {
                        // A style line with a pathological first field still
                        // only costs a bounded parse; we do not retain the
                        // definition itself here (the renderer reads names).
                        ++styleCount;
                    }
                }
                if (value.size() > ctx.lim.maxLineBytes)
                    ctx.markLimit();
            }
            continue;
        }

        // ---- [Fonts]: fontname: data lines --------------------------------
        if (section == Section::Fonts) {
            if (!ctx.policy.allowEmbeddedFonts) continue;
            if (fontCount >= ctx.lim.maxFonts) {
                ctx.diag.warning(ln, "font.count", "maxFonts reached");
                ctx.markLimit();
                continue;
            }
            if (iequals(key, "fontname")) {
                FontData fd;
                assignCapped(ctx, fd.family, value, ctx.lim.maxStyleNameBytes);
                assignCapped(ctx, fd.sourceName, value,
                             ctx.lim.maxStyleNameBytes);
                ctx.result.fonts.push_back(std::move(fd));
                currentFont = &ctx.result.fonts.back();
                ++fontCount;
            }
            continue;
        }
        if (section == Section::Graphics) {
            // Embedded raster graphics are never retained.
            continue;
        }

        // ---- [Events] Dialogue / Comment ----------------------------------
        if (section == Section::Events &&
            (iequals(key, "Dialogue") || iequals(key, "Comment") ||
             (!haveEventFormat && legacySsa))) {
            bool isComment = iequals(key, "Comment");

            // Split only the structured prefix; Text is the remainder and may
            // itself contain commas, so use a high-part split then rejoin.
            std::string_view parts[16];
            size_t np = splitView(value, ',', parts, 16);

            int iStart = haveEventFormat ? eventIndex[1] : 1;
            int iEnd   = haveEventFormat ? eventIndex[2] : 2;
            int iStyle = haveEventFormat ? eventIndex[3] : 3;
            int iText  = haveEventFormat ? eventIndex[9] : int(np) - 1;
            if (iStart < 0 || iEnd < 0 || iText < 0 ||
                size_t(iStart) >= np || size_t(iEnd) >= np ||
                size_t(iText) >= np) {
                ctx.diag.warning(ln, "ass.event_fields",
                                 "event missing required fields; dropped");
                ++ctx.result.droppedCues;
                continue;
            }

            Cue cue;
            if (!parseAssTime(ctx, ln, parts[iStart], cue.startMs) ||
                !parseAssTime(ctx, ln, parts[iEnd], cue.endMs)) {
                ctx.diag.warning(ln, "ass.bad_time",
                                 "unparseable event timestamp; cue dropped");
                ++ctx.result.droppedCues;
                continue;
            }

            if (iStyle >= 0 && size_t(iStyle) < np)
                assignCapped(ctx, cue.styleName, trim(parts[iStyle]),
                             ctx.lim.maxStyleNameBytes);

            // Rejoin everything from the Text field onward (commas in text).
            std::string text(parts[iText].data(), parts[iText].size());
            for (size_t k = size_t(iText) + 1; k < np; ++k) {
                text.push_back(',');
                text.append(parts[k].data(), parts[k].size());
            }
            if (text.size() > ctx.lim.maxCueTextBytes)
                text.resize(ctx.lim.maxCueTextBytes);
            cue.text = std::move(text);

            finishCueText(ctx, cue, InlineTagMode::AssOverride, nullptr);
            normalizeRange(ctx, ln, cue);

            if (isComment) continue;   // comments parse but are not displayed
            if (!cue.empty()) ctx.addCue(std::move(cue));
            continue;
        }
    }
}

} // namespace subsafe::detail
