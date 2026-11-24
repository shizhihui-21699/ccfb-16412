// SPDX-License-Identifier: MIT
// Internal hardening primitives shared by every format parser.
//
// Nothing in this header is part of the public ABI. The design rule is that
// parsers cannot touch the raw input except through BoundedReader and cannot
// grow output except through Budget / the capped helpers, so a single missed
// check in a format parser cannot turn into an out-of-bounds write.
#pragma once

#include "subsafe/limits.h"
#include "subsafe/style_policy.h"
#include "subsafe/types.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace subsafe::detail {

// ---------------------------------------------------------------------------
// Output byte budget. Every byte placed into result-owned strings is
// reserved here first. All arithmetic is overflow-checked: `take(n)` only
// ever compares n against cap_-used_ where used_ <= cap_ is an invariant.
// ---------------------------------------------------------------------------
class Budget {
public:
    explicit Budget(size_t cap) noexcept : cap_(cap) {}

    bool canFit(size_t n) const noexcept { return n <= cap_ - used_; }

    // Reserve n bytes. On overflow the budget is saturated and false returned;
    // the caller must truncate/drop rather than retry with a smaller guess.
    bool take(size_t n) noexcept {
        if (n > cap_ - used_) {
            used_ = cap_;
            return false;
        }
        used_ += n;
        return true;
    }

    size_t used() const noexcept { return used_; }
    size_t remaining() const noexcept { return cap_ - used_; }

private:
    size_t cap_;
    size_t used_ = 0;
};

// ---------------------------------------------------------------------------
// Diagnostic recording with a hard cap on how many full records are stored.
// ---------------------------------------------------------------------------
class DiagSink {
public:
    DiagSink(ParseResult& res, const ParserLimits& lim) noexcept
        : res_(res), lim_(lim) {}

    void report(Severity sev, size_t line, std::string_view code,
                std::string_view msg);

    // Convenience wrappers.
    void warning(size_t line, std::string_view code, std::string_view msg) {
        report(Severity::Warning, line, code, msg);
    }
    void error(size_t line, std::string_view code, std::string_view msg) {
        report(Severity::Error, line, code, msg);
    }
    void fatal(std::string_view code, std::string_view msg) {
        report(Severity::Fatal, 0, code, msg);
    }

private:
    ParseResult& res_;
    const ParserLimits& lim_;
};

// Thrown only for unrecoverable, whole-file aborts (e.g. input over the hard
// cap). Caught by the facade; format parsers prefer per-cue diagnostics.
class FatalAbort {
public:
    explicit FatalAbort(std::string code) : code_(std::move(code)) {}
    const std::string& code() const noexcept { return code_; }
private:
    std::string code_;
};

// ---------------------------------------------------------------------------
// BoundedReader: owns normalized UTF-8 storage and hands out line views.
// Views are valid only while the reader lives; parsers must copy anything
// they retain, through the Budget.
// ---------------------------------------------------------------------------
class BoundedReader {
public:
    BoundedReader(std::string_view raw, const ParserLimits& lim,
                  DiagSink& diag);

    // One physical line (EOL stripped, trailing '\r' removed). Empty lines
    // are returned normally. Returns false at EOF, or after maxLines lines
    // (records a diagnostic and sets result.limitHit once).
    bool nextLine(std::string_view& out) noexcept;

    size_t lineNumber() const noexcept { return lineNo_; }
    std::string_view text() const noexcept { return decoded_; }
    bool wasTranscoded() const noexcept { return transcoded_; }

private:
    void decode();   // BOM strip + UTF-16 transcode + hard input cap

    std::string_view raw_;
    std::string decoded_;          // empty unless transcoding was needed
    std::string_view view_;        // active window over decoded_ or raw_
    const ParserLimits& lim_;
    DiagSink& diag_;
    size_t lineNo_ = 0;
    size_t pos_ = 0;
    bool transcoded_ = false;
    bool lineBudgetReported_ = false;
};

// ---------------------------------------------------------------------------
// Parse context bundled into one reference passed down every parser.
// ---------------------------------------------------------------------------
struct ParseContext {
    const ParserLimits& lim;
    const StylePolicy& policy;
    ParseResult& result;
    Budget budget;
    DiagSink diag;

    ParseContext(std::string_view /*tag*/, const ParserLimits& l,
                 const StylePolicy& p, ParseResult& r)
        : lim(l), policy(p), result(r),
          budget(l.maxTextBudgetBytes), diag(r, l) {}

    // Append src to dst under both a per-field cap and the global budget.
    // Returns false if either bound was hit (dst holds the safe prefix).
    bool appendCapped(std::string& dst, std::string_view src, size_t fieldCap);

    // Retain a cue, enforcing maxCues and the global text budget (the cue's
    // strings are already budget-charged; this covers the fixed overhead).
    bool addCue(Cue cue);

    void markLimit() noexcept { result.limitHit = true; }
};

// ---------------------------------------------------------------------------
// Numeric parsing — every entry point is noexcept and overflow-aware.
// ---------------------------------------------------------------------------
bool parseInt64(std::string_view s, int64_t& out) noexcept;
bool parseUint64(std::string_view s, uint64_t& out) noexcept;

// Hand-rolled fixed parser (no locale, no errno, no float-format CVEs).
// Rejects NaN/Inf, exponent abuse and absurd digit counts; returns false
// outside [-absMax, absMax].
bool parseBoundedDouble(std::string_view s, double& out,
                        double absMax = 1e12) noexcept;

// Clamp an already-parsed timestamp into the configured timeline window.
int64_t clampTime(int64_t ms, const ParserLimits& lim) noexcept;

// Generic signed clamp (no UB: inputs are compared before narrowing).
int32_t clampInt(int64_t v, int32_t lo, int32_t hi) noexcept;

// "H:MM:SS.frac" / "MM:SS.frac" / "SS.frac" with '.' or ',' fraction
// separator. Out-of-range fields are clamped (with a warning through ctx)
// rather than dropping the cue. Returns false only when no numbers exist.
bool parseHmsMs(ParseContext& ctx, size_t lineNo, std::string_view s,
                int64_t& outMs) noexcept;

// Frame-count based formats (MicroDVD, MPL2, PJS). Overflow-checked.
bool framesToMs(uint64_t frame, double fps, int64_t& outMs) noexcept;

// ---------------------------------------------------------------------------
// String helpers — all bounds-aware, all ASCII-case (subtitle keywords are
// ASCII; UTF-8 casing is intentionally not touched).
// ---------------------------------------------------------------------------
std::string_view trim(std::string_view s) noexcept;
bool iequals(std::string_view a, std::string_view b) noexcept;
bool istartsWith(std::string_view s, std::string_view prefix) noexcept;
bool iendsWith(std::string_view s, std::string_view suffix) noexcept;

// Split into at most maxParts views on delim. Returns number of parts; the
// final part contains the unsplit remainder. Never allocates on the heap.
size_t splitView(std::string_view s, char delim, std::string_view* out,
                 size_t maxParts) noexcept;

// ASS/SSA use comma-separated fields; same bounded splitter, named for
// readability at call sites.
inline size_t splitComma(std::string_view s, std::string_view* out,
                         size_t maxParts) noexcept {
    return splitView(s, ',', out, maxParts);
}

// Copy into a length-capped, budget-charged string.
bool assignCapped(ParseContext& ctx, std::string& dst,
                  std::string_view src, size_t fieldCap);

// UTF-8: replace invalid sequences / lone surrogates with U+FFFD, strip NUL.
// Output growth is charged to ctx.budget.
std::string sanitizeUtf8(ParseContext& ctx, std::string_view s);

// Join physical lines into a cue text with '\n', capped.
bool appendCueLine(ParseContext& ctx, std::string& text,
                   std::string_view line);

} // namespace subsafe::detail
