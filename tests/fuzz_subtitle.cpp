// SPDX-License-Identifier: MIT
// Fuzz target. Build with -DSUBSAFE_FUZZ=ON and a fuzzing engine
// (libFuzzer via -fsanitize=fuzzer,address,undefined). The entry point also
// accepts a file argument under a normal (non-fuzzer) build so it can be run
// as a one-shot crash reproducer.
#include "subsafe/subsafe.h"
#include "subsafe/capi.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace subsafe;

static void exercise(const uint8_t* data, size_t size) {
    // Drive every code path with several policies so sanitizer decisions are
    // exercised, not just the default-deny configuration.
    for (int policy = 0; policy < 3; ++policy) {
        ParserLimits lim = ParserLimits::defaults();
        StylePolicy sp = StylePolicy::defaultPolicy();
        if (policy == 1) sp = StylePolicy::permissive();
        if (policy == 2) {
            // Tight limits to hammer the budget/boundary branches.
            lim.maxCues = 50;
            lim.maxCueTextBytes = 256;
            lim.maxInputBytes = 4096;
            lim.maxDepth = 4;
            sp.allowEmbeddedFonts = true;
        }
        ParseResult r = parse(data, size, lim, sp);

        // Post-parse invariants that must hold for ANY input.
        for (const Cue& c : r.cues) {
            if (c.startMs < 0 || c.endMs < c.startMs) std::abort();
            if (c.text.size() > lim.maxCueTextBytes) std::abort();
        }
        for (const FontData& f : r.fonts)
            if (f.bytes.size() > lim.maxFontBytes) std::abort();

        // The C ABI must agree and stay sound on the same bytes.
        subsafe_result_t* cr = subsafe_parse(data, size, SUBSAFE_FMT_AUTO,
                                             policy == 1 ? 1 : 0, 0);
        if (!cr) std::abort();
        for (size_t i = 0; i < subsafe_result_cue_count(cr); ++i) {
            const subsafe_cue_t* cue = subsafe_result_get_cue(cr, i);
            if (!cue || !cue->text) std::abort();
        }
        subsafe_result_free(cr);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    exercise(data, size);
    return 0;
}

#if defined(SUBSAFE_STANDALONE_FUZZ)
int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <corpus-file>...\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; ++i) {
        std::ifstream in(argv[i], std::ios::binary);
        if (!in) continue;
        std::ostringstream ss;
        ss << in.rdbuf();
        std::string buf = ss.str();
        exercise(reinterpret_cast<const uint8_t*>(buf.data()), buf.size());
        std::printf("ok: %s (%zu bytes)\n", argv[i], buf.size());
    }
    return 0;
}
#endif
