// SPDX-License-Identifier: MIT
// Public facade: format detection + exception-safe parse entry point.
#pragma once

#include "subsafe/limits.h"
#include "subsafe/style_policy.h"
#include "subsafe/types.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace subsafe {

// Human-readable name for diagnostics/logging.
const char* formatName(Format f) noexcept;

// Infer a format from content (authoritative) and, as a tie-breaker, the
// file name extension. Never throws; returns Format::Auto only when nothing
// matches (the caller can then force a format or reject the file).
Format detectFormat(std::string_view content,
                    std::string_view fileName = {}) noexcept;

// The one call a player needs. Guarantees:
//   * never throws (including std::bad_alloc — translated to a Fatal result),
//   * never reads beyond [data, data+size),
//   * never retains a reference to `data` after returning,
//   * a malformed file yields partial cues + diagnostics, not a crash.
// `forced == Format::Auto` uses detection; otherwise the given parser is used
// and detection failures are ignored.
ParseResult parse(const uint8_t* data, size_t size,
                  const ParserLimits& limits = ParserLimits::defaults(),
                  const StylePolicy& policy = StylePolicy::defaultPolicy(),
                  Format forced = Format::Auto) noexcept;

inline ParseResult parse(std::string_view text,
                         const ParserLimits& limits = ParserLimits::defaults(),
                         const StylePolicy& policy = StylePolicy::defaultPolicy(),
                         Format forced = Format::Auto) noexcept {
    return parse(reinterpret_cast<const uint8_t*>(text.data()), text.size(),
                 limits, policy, forced);
}

} // namespace subsafe
