// SPDX-License-Identifier: MIT
// Style-script capability policy ("style sandbox").
//
// ASS/SSA and a few other formats embed a small scripting-ish override
// language inside cue text (e.g. {\an8\move(...)\t(...)\p1...}). Historically
// renderers implemented these with generous parsers and dynamic allocation
// driven directly by file-supplied numbers — the source of the heap-overflow
// class described in the threat model. This module decides, *before the
// renderer ever sees a tag*, which capabilities are allowed and clamps every
// numeric argument to a fixed range. It performs no allocation proportional to
// attacker-controlled counts.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace subsafe {

struct StylePolicy {
    // --- Dangerous control-flow / dynamic capabilities --------------------
    // \move and \t (animated transforms) drive per-frame reallocation and
    // interpolation. They are the classic DoS/RCE surface. Default: strip.
    bool allowMove = false;
    bool allowAnimatedTransform = false;   // \t
    bool allowKaraoke = true;              // \k et al. — timing only, cheap
    bool allowWrapHints = true;            // \q, \n, \N

    // --- Vector drawing ---------------------------------------------------
    // \p drawing blocks can contain millions of commands. Default: strip the
    // block entirely. If enabled, command counts are still capped by
    // ParserLimits::maxDrawingCommands and coordinates clamped.
    bool allowVectorDrawing = false;

    // --- Embedded fonts ---------------------------------------------------
    // When false, [Fonts] sections / data: URIs are skipped at parse time so
    // no font bytes are even retained. When true, fonts are kept as raw,
    // length-capped blobs for the renderer's own (separate) validation.
    bool allowEmbeddedFonts = false;

    // --- Blur / glow / bevel (expensive raster effects) -------------------
    // Kept as clamped scalars; huge radii are folded to a maximum rather than
    // driving unbounded kernel allocation.
    bool allowBlur = true;
    int32_t maxEffectRadiusPx = 64;

    // --- Geometry clamps --------------------------------------------------
    int32_t maxCoordPx = 7680;             // beyond 8K there is no real screen
    int32_t maxFontSize = 400;
    int32_t minFontSize = 4;
    int32_t maxAlpha = 255;
    int32_t maxColorChannels = 255;

    // --- Tag-length / nesting --------------------------------------------
    size_t maxTagBytes = 4096;             // one {...} override block
    unsigned maxTagNesting = 8;

    // When a disallowed tag is stripped, replace its text with nothing
    // (default) or with a visible marker for debugging.
    bool markStripped = false;

    // Preserve harmless inline text tags (\b \i \u \c &... &) so styling is
    // not lost for the huge body of real, well-behaved files.
    bool preserveInlineStyles = true;

    static StylePolicy defaultPolicy() noexcept { return StylePolicy{}; }
    // A maximally permissive policy (still clamps numbers). Useful only for
    // tests/tooling that want to inspect raw structure.
    static StylePolicy permissive() noexcept {
        StylePolicy p;
        p.allowMove = p.allowAnimatedTransform = true;
        p.allowVectorDrawing = p.allowEmbeddedFonts = true;
        return p;
    }
};

// Outcome of sanitizing one ASS override block.
struct TagAudit {
    bool strippedAny = false;     // at least one capability was removed
    bool clampedAny = false;      // at least one number was range-clamped
    size_t drawingCommands = 0;   // \p commands seen (capped during scan)
};

// Process a single ASS override block. `block` is the content INSIDE the
// braces (without them). Returns the rewritten block content (without
// braces). Never throws; on any anomaly returns an empty allowed block.
std::string sanitizeAssBlock(std::string_view block,
                             const StylePolicy& policy,
                             TagAudit& audit);

// Strip/clamp HTML-ish inline tags used by SRT/WebVTT/SAMI (<b>, <font ...>,
// and crucially junk like <script>, on*= handlers, javascript: URIs). Returns
// safe inline text. Unknown tags are removed but their inner text preserved.
std::string sanitizeHtmlInline(std::string_view text,
                               const StylePolicy& policy,
                               TagAudit& audit);

// Remove control characters that must never reach a renderer's text shaping
// (NUL, and the C1 set other than common whitespace). Operates in place-ish
// via returned string; keeps valid UTF-8 and '\n'.
std::string stripControlChars(std::string_view text);

} // namespace subsafe
