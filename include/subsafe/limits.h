// SPDX-License-Identifier: MIT
// Hard resource limits and the result/error contract.
//
// The single most important hardening property: every parser receives a
// ParserLimits struct and is *required* to stay inside it. Defaults are tuned
// for real-world subtitle files (including bloated fansub ASS scripts) while
// being small enough that a malicious file cannot exhaust memory or spend
// unbounded CPU. Every limit is overridable by the embedding player.
#pragma once

#include "types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace subsafe {

struct ParserLimits {
    // Reject inputs larger than this outright. 64 MiB dwarfs any legitimate
    // text subtitle; anything bigger is almost certainly a decompression bomb
    // or non-subtitle payload.
    size_t maxInputBytes = 64u * 1024u * 1024u;

    // Hard cap on decoded lines scanned. A 64 MiB file of one-byte lines would
    // otherwise mean ~64M loop iterations in parsers that iterate per line.
    size_t maxLines = 2'000'000;

    // Maximum number of cues retained. Also bounds every per-cue container.
    size_t maxCues = 200'000;

    // Aggregate ceiling on bytes allocated for cue text + style strings.
    // Checked before each growth so allocation size never comes from attacker
    // arithmetic. Generous vs. typical files (~1–3 MiB of text).
    size_t maxTextBudgetBytes = 32u * 1024u * 1024u;

    // Per-cue text cap. Kills the "one 100 MB style run" heap overflow class.
    size_t maxCueTextBytes = 64u * 1024u;

    // Single logical line cap (a style definition, a header field, ...).
    size_t maxLineBytes = 1u * 1024u * 1024u;

    // ASS style table entries and distinct style names.
    size_t maxStyles = 10'000;
    size_t maxStyleNameBytes = 128;

    // Embedded font handling.
    size_t maxFonts = 64;
    size_t maxFontBytes = 8u * 1024u * 1024u;   // per font
    size_t maxFontTotalBytes = 32u * 1024u * 1024u;

    // Nested structure depth (JSON objects/arrays, nested tags).
    unsigned maxDepth = 32;

    // Numeric ranges for timeline values.
    int64_t maxTimestampMs = 24LL * 60LL * 60LL * 1000LL; // 24 h is plenty
    int64_t maxCueDurationMs = 12LL * 60LL * 60LL * 1000LL;

    // ASS drawing vector instruction count (\\p blocks). A real effect rarely
    // exceeds a few thousand; millions are a CPU/heap DoS.
    size_t maxDrawingCommands = 200'000;

    // How many malformed cues we record in detail. Diagnostics beyond this are
    // counted but not stored, so the error list itself can't be used to OOM.
    size_t maxStoredDiagnostics = 100;

    // Factory defaults, deliberately conservative.
    static ParserLimits defaults() noexcept { return ParserLimits{}; }
};

// Severity ordering: a parser that only ever emits Warnings still returns all
// recoverable cues. Errors mean some input was dropped; Fatal means no cues.
enum class Severity { Note, Warning, Error, Fatal };

struct Diagnostic {
    Severity severity = Severity::Note;
    size_t   line = 0;          // 1-based source line, 0 if N/A
    std::string code;           // stable machine-readable id, e.g. "time.range"
    std::string message;        // human-readable, never embeds huge input slices
};

// The entire return value. parse() never throws: any internal exception
// (including std::bad_alloc) is translated into a Fatal diagnostic and the
// work done so far is returned. A player can therefore call parse() on the
// playback hot path with no try/catch and no crash risk.
struct ParseResult {
    Format format = Format::Auto;
    std::vector<Cue> cues;
    std::vector<FontData> fonts;
    std::vector<Diagnostic> diagnostics;

    // Counts that can exceed maxStoredDiagnostics.
    size_t droppedCues = 0;
    size_t suppressedDiagnostics = 0;
    bool   limitHit = false;     // any ParserLimits ceiling was reached

    bool ok() const noexcept {
        for (const auto& d : diagnostics)
            if (d.severity == Severity::Fatal) return false;
        return true;
    }
    size_t errorCount() const noexcept {
        size_t n = 0;
        for (const auto& d : diagnostics)
            if (d.severity == Severity::Error || d.severity == Severity::Fatal)
                ++n;
        return n;
    }
};

} // namespace subsafe
