// SPDX-License-Identifier: MIT
#include "subsafe/capi.h"
#include "subsafe/subsafe.h"

#include <new>
#include <string>
#include <vector>

using subsafe::Cue;
using subsafe::Diagnostic;
using subsafe::Format;
using subsafe::ParseResult;
using subsafe::ParserLimits;
using subsafe::Severity;
using subsafe::StylePolicy;

namespace {

Format mapFormat(subsafe_format_t f) {
    switch (f) {
        case SUBSAFE_FMT_SRT: return Format::Srt;
        case SUBSAFE_FMT_VTT: return Format::WebVtt;
        case SUBSAFE_FMT_ASS: return Format::Ass;
        case SUBSAFE_FMT_SSA: return Format::Ssa;
        case SUBSAFE_FMT_MICRODVD: return Format::MicroDvd;
        case SUBSAFE_FMT_SAMI: return Format::Sami;
        case SUBSAFE_FMT_PJS: return Format::Pjs;
        case SUBSAFE_FMT_JSON: return Format::TedJson;
        case SUBSAFE_FMT_SBV: return Format::Sbv;
        case SUBSAFE_FMT_LRC: return Format::Lrc;
        case SUBSAFE_FMT_MPL2: return Format::Mpl2;
        case SUBSAFE_FMT_TMP: return Format::Tmp;
        default: return Format::Auto;
    }
}

subsafe_severity_t mapSeverity(Severity s) {
    switch (s) {
        case Severity::Warning: return SUBSAFE_SEV_WARNING;
        case Severity::Error:   return SUBSAFE_SEV_ERROR;
        case Severity::Fatal:   return SUBSAFE_SEV_FATAL;
        default:                return SUBSAFE_SEV_NOTE;
    }
}

subsafe_format_t mapBack(Format f) {
    switch (f) {
        case Format::Srt: return SUBSAFE_FMT_SRT;
        case Format::WebVtt: return SUBSAFE_FMT_VTT;
        case Format::Ass: return SUBSAFE_FMT_ASS;
        case Format::Ssa: return SUBSAFE_FMT_SSA;
        case Format::MicroDvd: return SUBSAFE_FMT_MICRODVD;
        case Format::Sami: return SUBSAFE_FMT_SAMI;
        case Format::Pjs: return SUBSAFE_FMT_PJS;
        case Format::TedJson: return SUBSAFE_FMT_JSON;
        case Format::Sbv: return SUBSAFE_FMT_SBV;
        case Format::Lrc: return SUBSAFE_FMT_LRC;
        case Format::Mpl2: return SUBSAFE_FMT_MPL2;
        case Format::Tmp: return SUBSAFE_FMT_TMP;
        default: return SUBSAFE_FMT_AUTO;
    }
}

} // namespace

struct subsafe_result {
    ParseResult parsed;
    std::vector<subsafe_cue_t> cues;
    std::vector<subsafe_diagnostic_t> diags;
};

extern "C" subsafe_result_t* subsafe_parse(const uint8_t* data, size_t size,
                                           subsafe_format_t forced,
                                           int allow_embedded_fonts,
                                           int allow_vector_drawing) {
    auto* r = new (std::nothrow) subsafe_result();
    if (!r) return nullptr;

    StylePolicy policy = StylePolicy::defaultPolicy();
    policy.allowEmbeddedFonts = allow_embedded_fonts != 0;
    policy.allowVectorDrawing = allow_vector_drawing != 0;

    r->parsed = subsafe::parse(data, size, ParserLimits::defaults(), policy,
                               mapFormat(forced));

    r->cues.reserve(r->parsed.cues.size());
    for (const Cue& c : r->parsed.cues) {
        subsafe_cue_t out{};
        out.start_ms = c.startMs;
        out.end_ms = c.endMs;
        out.text = c.text.c_str();
        out.pos_x = c.posX;
        out.pos_y = c.posY;
        out.layer = c.layer;
        out.style = c.styleName.c_str();
        r->cues.push_back(out);
    }
    r->diags.reserve(r->parsed.diagnostics.size());
    for (const Diagnostic& d : r->parsed.diagnostics) {
        subsafe_diagnostic_t out{};
        out.severity = mapSeverity(d.severity);
        out.line = d.line;
        out.code = d.code.c_str();
        out.message = d.message.c_str();
        r->diags.push_back(out);
    }
    return r;
}

extern "C" size_t subsafe_result_cue_count(const subsafe_result_t* r) {
    return r ? r->cues.size() : 0;
}
extern "C" const subsafe_cue_t* subsafe_result_get_cue(
    const subsafe_result_t* r, size_t index) {
    if (!r || index >= r->cues.size()) return nullptr;
    return &r->cues[index];
}
extern "C" size_t subsafe_result_diag_count(const subsafe_result_t* r) {
    return r ? r->diags.size() : 0;
}
extern "C" const subsafe_diagnostic_t* subsafe_result_get_diag(
    const subsafe_result_t* r, size_t index) {
    if (!r || index >= r->diags.size()) return nullptr;
    return &r->diags[index];
}
extern "C" int subsafe_result_ok(const subsafe_result_t* r) {
    return (r && r->parsed.ok()) ? 1 : 0;
}
extern "C" int subsafe_result_limit_hit(const subsafe_result_t* r) {
    return (r && r->parsed.limitHit) ? 1 : 0;
}
extern "C" subsafe_format_t subsafe_result_format(const subsafe_result_t* r) {
    return r ? mapBack(r->parsed.format) : SUBSAFE_FMT_AUTO;
}
extern "C" void subsafe_result_free(subsafe_result_t* r) { delete r; }
