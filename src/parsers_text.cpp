// SPDX-License-Identifier: MIT
// SRT and WebVTT parsers. Both are block-oriented and share most of their
// malformed-input handling: an unparseable header/timing line drops only the
// current block, never the file.
#include "internal/parsers.h"

#include <array>

namespace subsafe::detail {

namespace {

// Parse "HH:MM:SS,mmm --> HH:MM:SS,mmm" (SRT, comma) or the VTT dot variant.
// Returns the number of chars consumed from `line` on success, 0 on failure.
size_t parseArrowTimes(ParseContext& ctx, size_t lineNo,
                       std::string_view line, Cue& cue, bool vtt) {
    size_t arrow = line.find("-->");
    if (arrow == std::string_view::npos) return 0;
    std::string_view left = trim(line.substr(0, arrow));
    std::string_view rest = trim(line.substr(arrow + 3));

    // The right timestamp ends at the first whitespace; anything after is
    // cue settings (VTT) or junk we must ignore safely.
    size_t sp = rest.find_first_of(" \t");
    std::string_view right = (sp == std::string_view::npos)
                                 ? rest : rest.substr(0, sp);

    if (!parseHmsMs(ctx, lineNo, left, cue.startMs)) return 0;
    if (!parseHmsMs(ctx, lineNo, right, cue.endMs)) return 0;

    if (vtt && sp != std::string_view::npos) {
        // Parse only positional settings; discard style/line payload safely.
        std::string_view settings = rest.substr(sp + 1);
        std::string_view toks[16];
        size_t n = splitView(settings, ' ', toks, 16);
        for (size_t t = 0; t < n; ++t) {
            std::string_view kv = trim(toks[t]);
            size_t colon = kv.find(':');
            if (colon == std::string_view::npos) continue;
            std::string_view key = kv.substr(0, colon);
            std::string_view val = kv.substr(colon + 1);
            if (key == "position" || key == "line") {
                int64_t v = 0;
                if (parseInt64(val, v)) {
                    int32_t clamped = clampInt(v, -ctx.policy.maxCoordPx,
                                               ctx.policy.maxCoordPx);
                    if (key == "position") cue.posX = clamped;
                    else cue.posY = clamped;
                }
            }
            // align/region/vertical/size intentionally ignored.
        }
    }
    (void)vtt;
    return arrow + 3 + right.size();
}

// Drive a block-oriented parser. `readBlock` pulls cue text lines until the
// next blank line and is supplied per-format because headers differ.
template <typename HeaderFn>
void parseBlockFormat(ParseContext& ctx, std::string_view raw,
                      bool expectNumericIndex, bool vtt, HeaderFn onHeader) {
    BoundedReader rd(raw, ctx.lim, ctx.diag);
    std::string_view line;
    Cue cue;
    bool haveCue = false;
    bool skipBlock = false;
    std::string text;

    auto flush = [&](size_t ln) {
        if (!haveCue) return;
        cue.text = std::move(text);
        text.clear();
        finishCueText(ctx, cue, InlineTagMode::HtmlInline, nullptr);
        normalizeRange(ctx, ln, cue);
        if (!cue.empty()) ctx.addCue(std::move(cue));
        cue = Cue{};
        haveCue = false;
    };

    while (rd.nextLine(line)) {
        size_t ln = rd.lineNumber();
        std::string_view t = trim(line);

        if (t.empty()) { flush(ln); skipBlock = false; continue; }
        if (skipBlock) continue;       // inside NOTE/STYLE/REGION body

        if (!haveCue) {
            // Optional cue index (SRT numeric, VTT optional identifier).
            if (expectNumericIndex) {
                int64_t idx = 0;
                if (parseInt64(t, idx) && t.find(':') == std::string_view::npos)
                    continue;   // consume numeric index line
            } else if (onHeader(t)) {
                // WEBVTT signature, or a NOTE/STYLE/REGION block opener whose
                // entire body up to the next blank line is discarded.
                if (istartsWith(t, "NOTE") || istartsWith(t, "STYLE") ||
                    istartsWith(t, "REGION"))
                    skipBlock = true;
                continue;
            }

            Cue candidate;
            if (parseArrowTimes(ctx, ln, line, candidate, vtt) != 0) {
                cue = std::move(candidate);
                haveCue = true;
                continue;
            }
            // VTT cue identifier lines (no arrow) are consumed silently; any
            // other stray line is reported but never aborts the file.
            if (!vtt)
                ctx.diag.warning(ln, "cue.header_skipped",
                                 "unexpected line outside a cue ignored");
            continue;
        }

        // Inside a cue: accumulate text under the per-cue cap.
        if (!appendCueLine(ctx, text, t))
            ctx.diag.warning(ln, "cue.text_truncated", "cue text capped");
    }
    flush(rd.lineNumber());
}

} // namespace

void parseSrt(ParseContext& ctx, std::string_view raw) {
    parseBlockFormat(ctx, raw, /*expectNumericIndex=*/true,
                     /*vtt=*/false, [](std::string_view) { return false; });
}

void parseVtt(ParseContext& ctx, std::string_view raw) {
    bool sawHeader = false;
    parseBlockFormat(ctx, raw, /*expectNumericIndex=*/false,
                     /*vtt=*/true, [&](std::string_view t) -> bool {
        if (!sawHeader) {
            sawHeader = true;
            if (istartsWith(t, "WEBVTT")) return true;
        }
        // Block-level constructs: their whole body is skipped by the caller's
        // blank-line flush, so just swallow the opening line.
        return istartsWith(t, "NOTE") || istartsWith(t, "STYLE") ||
               istartsWith(t, "REGION");
    });
}

} // namespace subsafe::detail
