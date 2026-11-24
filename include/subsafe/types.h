// SPDX-License-Identifier: MIT
// libsubsafe: hardened subtitle parsing library — public type definitions.
//
// All data exchanged across the library boundary lives in these plain,
// owning value types. Parsers never hand out pointers into the input buffer,
// so callers can free/reuse the source buffer immediately after parse().
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace subsafe {

// Every supported external subtitle container. kAuto lets the facade sniff
// the format; everything else forces a specific parser.
enum class Format {
    Auto,
    Srt,
    WebVtt,
    Ass,   // Advanced SubStation Alpha (.ass)
    Ssa,   // legacy SubStation Alpha v4 (.ssa)
    MicroDvd,  // .sub frame-based
    Sami,  // .smi / .sami Synchronized Accessible Media Interchange
    Pjs,   // .psb Phoenix Subtitle
    TedJson, // TED-style timed-text JSON
    Sbv,   // YouTube .sbv
    Lrc,   // lyrics .lrc
    Mpl2,  // .mpl
    Tmp,   // .tmp
    // Number of real formats (excluding Auto). Keep last.
    Count_
};

// A single rendered subtitle event. Times are milliseconds relative to the
// media timeline. Text is already sanitized according to the active
// StylePolicy; tags that the policy allowed are kept as literal text for the
// renderer, everything dangerous has been stripped or neutralized.
struct Cue {
    int64_t startMs = 0;
    int64_t endMs   = 0;
    std::string text;

    // Optional layout hints parsed from positional tags. The renderer is free
    // to ignore them. Negative = "not specified". They are clamped to a sane
    // range by the parser, never trusted blindly.
    int32_t posX = -1;
    int32_t posY = -1;
    int32_t layer = 0;

    // Name of the style this cue references (ASS "Style:" line, VTT cue
    // settings class, ...). Empty = default. Bounded in length.
    std::string styleName;

    bool empty() const noexcept { return text.empty(); }
};

// An embedded font pulled out of an ASS [Fonts] section or a data: URI.
// Raw bytes are kept (never executed/loaded by this library); the renderer
// decides whether to hand them to a font engine after its own validation.
struct FontData {
    std::string family;            // normalized, length-capped
    std::string sourceName;        // original file name as declared, capped
    std::vector<uint8_t> bytes;    // capped at ParserLimits::maxFontBytes

    // Bounded append. Returns false (and marks full) if the cap would be
    // exceeded; the caller skips the remainder instead of reallocating.
    bool append(const uint8_t* p, size_t n, size_t cap) noexcept {
        if (full) return false;
        if (n > cap - bytes.size()) {           // subtraction cannot underflow
            bytes.insert(bytes.end(), p, p + (cap - bytes.size()));
            full = true;
            return false;
        }
        bytes.insert(bytes.end(), p, p + n);
        return true;
    }
    bool full = false;
};

} // namespace subsafe
