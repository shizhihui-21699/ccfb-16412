// SPDX-License-Identifier: MIT
// Minimal player integration example.
//
// Shows the intended hot-path usage: a subtitle file is treated as fully
// untrusted, parsed once into bounded owning data, and the resulting cues are
// queried by the render loop. parse() cannot throw and cannot retain the
// input buffer, so this is safe to call from the playback thread.
//
// Build (after cmake --build):
//   clang++ -std=c++17 -Iinclude player_integration.cpp libsubsafe.a -o demo
#include "subsafe/subsafe.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace subsafe;

namespace {

// Everything the render loop needs per visible cue. The player owns this;
// no library pointer escapes parse().
struct VisibleCue {
    int64_t startMs, endMs;
    std::string text;
};

std::string readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <subtitle-file>\n", argv[0]);
        return 2;
    }

    // 1) Tune limits/policy once. Defaults are already conservative; a player
    //    can tighten them (e.g. embedded screens never need a 64MB subtitle).
    ParserLimits limits = ParserLimits::defaults();
    StylePolicy policy = StylePolicy::defaultPolicy();
    // Embedded fonts and vector drawing stay OFF unless you trust the source.
    // policy.allowEmbeddedFonts = true;

    // 2) Parse untrusted bytes. No try/catch required: the call is noexcept
    //    and turns even std::bad_alloc into a Fatal diagnostic.
    std::string raw = readFile(argv[1]);
    ParseResult result = parse(
        reinterpret_cast<const uint8_t*>(raw.data()), raw.size(),
        limits, policy, Format::Auto);

    std::printf("format=%s ok=%d cues=%zu warnings/errors=%zu limitHit=%d\n",
                formatName(result.format), result.ok(), result.cues.size(),
                result.diagnostics.size(), result.limitHit);

    // 3) Copy into the player's own representation. After this, the library
    //    types can be destroyed; nothing aliases the source buffer.
    std::vector<VisibleCue> cues;
    cues.reserve(result.cues.size());
    for (const Cue& c : result.cues)
        cues.push_back({c.startMs, c.endMs, c.text});

    // 4) The render loop query: binary search over sorted start times would
    //    go here. We just demonstrate the time-containment contract, which is
    //    guaranteed normalized (start <= end, both within the timeline cap).
    int64_t playheadMs = 1500;
    for (const auto& c : cues) {
        if (playheadMs >= c.startMs && playheadMs < c.endMs)
            std::printf("render at %lldms: %s\n",
                        static_cast<long long>(playheadMs), c.text.c_str());
    }

    // Diagnostics are operational telemetry: a non-ok result still carries
    // every cue that could be salvaged, so playback continues regardless.
    if (!result.ok())
        std::printf("note: file had fatal issues; salvaged %zu cues\n",
                    cues.size());
    return 0;
}
