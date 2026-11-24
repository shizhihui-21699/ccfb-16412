// SPDX-License-Identifier: MIT
// Internal parser entry points. Each parser consumes the whole input through
// a BoundedReader and appends to ctx.result. They may throw FatalAbort for
// whole-file conditions (caught by the facade); per-cue failures are emitted
// as diagnostics and never propagate.
#pragma once

#include "internal/common.h"

namespace subsafe::detail {

// Final sanitization shared by every parser before a cue is retained:
// control-char strip -> UTF-8 repair -> format-specific inline tag policy.
// ASS text keeps override blocks; HTML-ish formats use the HTML sanitizer.
enum class InlineTagMode { AssOverride, HtmlInline, Plain };

void finishCueText(ParseContext& ctx, Cue& cue, InlineTagMode mode,
                   TagAudit* auditOut = nullptr);

// Validate/normalize a time range: negative/overflow handled, end < start
// repaired by swapping (real-world files do this) with a warning.
void normalizeRange(ParseContext& ctx, size_t lineNo, Cue& cue);

// Parser entry points (one per format).
void parseSrt(ParseContext& ctx, std::string_view raw);
void parseVtt(ParseContext& ctx, std::string_view raw);
void parseAss(ParseContext& ctx, std::string_view raw, bool legacySsa);
void parseMicroDvd(ParseContext& ctx, std::string_view raw);
void parseSami(ParseContext& ctx, std::string_view raw);
void parsePjs(ParseContext& ctx, std::string_view raw);
void parseTedJson(ParseContext& ctx, std::string_view raw);
void parseSbv(ParseContext& ctx, std::string_view raw);
void parseLrc(ParseContext& ctx, std::string_view raw);
void parseMpl2(ParseContext& ctx, std::string_view raw);
void parseTmp(ParseContext& ctx, std::string_view raw);

} // namespace subsafe::detail
