// SPDX-License-Identifier: MIT
// subsafe-check: command-line subtitle validator / risk inspector.
//
// Usage:
//   subsafe-check [--strict] [--allow-fonts] [--allow-drawing]
//                 [--format FMT] [--json] <file>...
//
// Exit status: 0 if every file parsed without Fatal errors, 1 otherwise.
// The tool never writes into the input directory and treats every file as
// untrusted; it is itself a usage example for the library.
#include "subsafe/subsafe.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace subsafe;

namespace {

const char* sevName(Severity s) {
    switch (s) {
        case Severity::Note:    return "note";
        case Severity::Warning: return "warning";
        case Severity::Error:   return "error";
        case Severity::Fatal:   return "fatal";
    }
    return "?";
}

Format parseFormatName(const std::string& n) {
    if (n == "srt") return Format::Srt;
    if (n == "vtt" || n == "webvtt") return Format::WebVtt;
    if (n == "ass") return Format::Ass;
    if (n == "ssa") return Format::Ssa;
    if (n == "microdvd" || n == "sub") return Format::MicroDvd;
    if (n == "sami" || n == "smi") return Format::Sami;
    if (n == "pjs" || n == "psb") return Format::Pjs;
    if (n == "json") return Format::TedJson;
    if (n == "sbv") return Format::Sbv;
    if (n == "lrc") return Format::Lrc;
    if (n == "mpl" || n == "mpl2") return Format::Mpl2;
    if (n == "tmp") return Format::Tmp;
    return Format::Auto;
}

bool checkFile(const std::string& path, const ParserLimits& lim,
               const StylePolicy& policy, Format forced, bool asJson) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "cannot open %s\n", path.c_str());
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    std::string data = ss.str();

    ParseResult r = parse(reinterpret_cast<const uint8_t*>(data.data()),
                          data.size(), lim, policy, forced);
    if (asJson) {
        std::printf("{\"file\":\"%s\",\"format\":\"%s\",\"cues\":%zu,"
                    "\"fonts\":%zu,\"ok\":%s,\"limitHit\":%s,"
                    "\"dropped\":%zu,\"diagnostics\":[",
                    path.c_str(), formatName(r.format), r.cues.size(),
                    r.fonts.size(), r.ok() ? "true" : "false",
                    r.limitHit ? "true" : "false", r.droppedCues);
        for (size_t i = 0; i < r.diagnostics.size(); ++i) {
            const auto& d = r.diagnostics[i];
            std::printf("%s{\"severity\":\"%s\",\"line\":%zu,\"code\":\"%s\"}",
                        i ? "," : "", sevName(d.severity), d.line,
                        d.code.c_str());
        }
        std::printf("]}\n");
    } else {
        std::printf("%s: %s, %zu cues, %zu fonts, %zu diagnostics%s\n",
                    path.c_str(), formatName(r.format), r.cues.size(),
                    r.fonts.size(), r.diagnostics.size(),
                    r.limitHit ? " [LIMIT HIT]" : "");
        for (const auto& d : r.diagnostics)
            std::printf("    %-7s L%-6zu %s: %s\n", sevName(d.severity),
                        d.line, d.code.c_str(), d.message.c_str());
    }
    return r.ok();
}

} // namespace

int main(int argc, char** argv) {
    ParserLimits lim = ParserLimits::defaults();
    StylePolicy policy = StylePolicy::defaultPolicy();
    Format forced = Format::Auto;
    bool asJson = false;
    std::vector<std::string> files;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--strict") {
            lim.maxInputBytes = 8u * 1024u * 1024u;
            lim.maxCues = 50000;
        } else if (a == "--allow-fonts") {
            policy.allowEmbeddedFonts = true;
        } else if (a == "--allow-drawing") {
            policy.allowVectorDrawing = true;
        } else if (a == "--allow-move") {
            policy.allowMove = true;
            policy.allowAnimatedTransform = true;
        } else if (a == "--json") {
            asJson = true;
        } else if (a == "--format" && i + 1 < argc) {
            forced = parseFormatName(argv[++i]);
        } else if (a == "--help" || a == "-h") {
            std::printf("usage: %s [options] <file>...\n", argv[0]);
            return 0;
        } else if (!a.empty() && a[0] == '-') {
            std::fprintf(stderr, "unknown option %s\n", a.c_str());
            return 2;
        } else {
            files.push_back(a);
        }
    }
    if (files.empty()) {
        std::fprintf(stderr, "no input files (try --help)\n");
        return 2;
    }

    int failures = 0;
    for (const auto& f : files)
        if (!checkFile(f, lim, policy, forced, asJson)) ++failures;
    return failures ? 1 : 0;
}
