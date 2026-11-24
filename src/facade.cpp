// SPDX-License-Identifier: MIT
#include "subsafe/subsafe.h"

#include "internal/common.h"
#include "internal/parsers.h"

#include <cstring>
#include <exception>
#include <new>

namespace subsafe {

using detail::BoundedReader;
using detail::DiagSink;
using detail::FatalAbort;
using detail::ParseContext;
using detail::iequals;
using detail::istartsWith;
using detail::trim;

const char* formatName(Format f) noexcept {
    switch (f) {
        case Format::Srt:      return "SubRip (.srt)";
        case Format::WebVtt:   return "WebVTT (.vtt)";
        case Format::Ass:      return "SubStation Alpha v4+ (.ass)";
        case Format::Ssa:      return "SubStation Alpha v4 (.ssa)";
        case Format::MicroDvd: return "MicroDVD (.sub)";
        case Format::Sami:     return "SAMI (.smi)";
        case Format::Pjs:      return "Phoenix Subtitle (.psb)";
        case Format::TedJson:  return "Timed-text JSON (.json)";
        case Format::Sbv:      return "YouTube SBV (.sbv)";
        case Format::Lrc:      return "Lyrics (.lrc)";
        case Format::Mpl2:     return "MPL2 (.mpl)";
        case Format::Tmp:      return "TMP (.tmp)";
        case Format::Auto:     return "auto-detect";
        default:               return "unknown";
    }
}

namespace {

std::string_view extensionOf(std::string_view name) noexcept {
    size_t slash = name.find_last_of("/\\");
    if (slash != std::string_view::npos) name.remove_prefix(slash + 1);
    size_t dot = name.rfind('.');
    if (dot == std::string_view::npos) return {};
    return name.substr(dot + 1);
}

Format fromExtension(std::string_view ext) noexcept {
    if (iequals(ext, "srt")) return Format::Srt;
    if (iequals(ext, "vtt")) return Format::WebVtt;
    if (iequals(ext, "ass")) return Format::Ass;
    if (iequals(ext, "ssa")) return Format::Ssa;
    if (iequals(ext, "sub")) return Format::MicroDvd;
    if (iequals(ext, "smi") || iequals(ext, "sami")) return Format::Sami;
    if (iequals(ext, "psb")) return Format::Pjs;
    if (iequals(ext, "json")) return Format::TedJson;
    if (iequals(ext, "sbv")) return Format::Sbv;
    if (iequals(ext, "lrc")) return Format::Lrc;
    if (iequals(ext, "mpl")) return Format::Mpl2;
    if (iequals(ext, "tmp")) return Format::Tmp;
    return Format::Auto;
}

// Strip a UTF-8/UTF-16 BOM for content sniffing purposes.
std::string_view stripBom(std::string_view s) noexcept {
    if (s.size() >= 3 && static_cast<unsigned char>(s[0]) == 0xEF &&
        static_cast<unsigned char>(s[1]) == 0xBB &&
        static_cast<unsigned char>(s[2]) == 0xBF)
        return s.substr(3);
    return s;
}

bool contains(std::string_view hay, std::string_view needle) noexcept {
    return hay.find(needle) != std::string_view::npos;
}

Format sniffContent(std::string_view in) noexcept {
    std::string_view s = stripBom(in);
    // Only sniff a bounded prefix; a multi-MB header must not cost us here.
    std::string_view head = s.substr(0, std::min(s.size(), size_t(8192)));

    // Explicit, high-confidence section/markup markers take precedence over
    // bracket/timestamp heuristics (ASS headers start with '[' too).
    if (istartsWith(trim(head), "WEBVTT")) return Format::WebVtt;
    if (contains(head, "[Script Info]") || contains(head, "[ScriptInfo]")) {
        // v4+ styles distinguish ASS from legacy SSA.
        return contains(head, "[V4+ Styles]") ? Format::Ass : Format::Ssa;
    }
    // ASS/SSA files may omit [Script Info] and open directly on a styles,
    // events or fonts section. Recognize those section headers too.
    if (contains(head, "[V4+ Styles]") || contains(head, "[V4 Styles]"))
        return contains(head, "[V4+ Styles]") ? Format::Ass : Format::Ssa;
    if (contains(head, "[Events]") || contains(head, "[Fonts]") ||
        contains(head, "[Graphics]"))
        return Format::Ass;
    if (contains(head, "<SAMI") || contains(head, "<sami"))
        return Format::Sami;
    if (contains(head, "SYNC") && contains(head, "<"))
        return Format::Sami;

    // JSON: a '{' that opens an object, or a '[' that opens an array with
    // structural evidence. Brace timestamps (MicroDVD) and bracket
    // timestamps (LRC/MPL2) are checked first below, so here we require the
    // second character to prove JSON rather than guess.
    std::string_view trimmed = trim(head);
    if (!trimmed.empty() && trimmed[0] == '{') {
        // MicroDVD {frame}{frame}: a brace of pure digits immediately
        // followed by a second brace. A JSON object's first brace contains a
        // quote/key, never a run of digits then '}{'. Frame counts can be
        // long, so validate by content rather than a fixed width.
        size_t c1 = trimmed.find('}');
        if (c1 != std::string_view::npos && c1 > 1 &&
            c1 + 1 < trimmed.size() && trimmed[c1 + 1] == '{') {
            bool allDigits = true;
            for (size_t k = 1; k < c1; ++k)
                if (!(trimmed[k] >= '0' && trimmed[k] <= '9')) allDigits = false;
            if (allDigits) return Format::MicroDvd;
        }
        return Format::TedJson;
    }
    if (trimmed.size() >= 2 && trimmed[0] == '[' &&
        (trimmed[1] == '{' || trimmed[1] == '[')) {
        return Format::TedJson;
    }

    // LRC: leading [mm:ss(.xx)] — a bracket, digits, and an internal colon
    // before the closing bracket.
    if (head.size() >= 4 && head[0] == '[' && head[1] >= '0' &&
        head[1] <= '9') {
        size_t c = head.find(']');
        if (c != std::string_view::npos && c < 12 &&
            head.find(':') < c)
            return Format::Lrc;
    }

    // MPL2: [digits][digits], two consecutive bracketed integers.
    if (head.size() >= 2 && head[0] == '[') {
        size_t c1 = head.find(']');
        if (c1 != std::string_view::npos && c1 + 1 < head.size() &&
            head[c1 + 1] == '[' && c1 < 12) {
            bool allDigits = true;
            for (size_t k = 1; k < c1; ++k)
                if (!(head[k] >= '0' && head[k] <= '9')) allDigits = false;
            if (allDigits) return Format::Mpl2;
        }
    }

    // MicroDVD without an object-style brace (already handled above), kept
    // as a defensive fallback.
    if (head.size() >= 2 && head[0] == '{') {
        size_t c1 = head.find('}');
        if (c1 != std::string_view::npos && c1 + 1 < head.size() &&
            head[c1 + 1] == '{')
            return Format::MicroDvd;
    }

    // SRT: numeric index then an "-->" timing line. SBV uses comma-separated
    // HH:MM:SS times without an index. Scan a small window of lines.
    bool sawArrow = contains(head, "-->");
    if (sawArrow) {
        // TMP also uses HH:MM:SS but no arrow; SRT/VTT are the arrow formats.
        // VTT was already handled above, so this is SRT.
        return Format::Srt;
    }
    if (contains(head, ":")) {
        // SBV "0:00:01.000,0:00:03.000" ; TMP "00:00:01 text".
        size_t nl = head.find('\n');
        std::string_view first = trim(head.substr(0,
            nl == std::string_view::npos ? head.size() : nl));
        if (first.find(',') != std::string_view::npos)
            return Format::Sbv;
        if (first.size() >= 8 && first[2] == ':' && first[5] == ':')
            return Format::Tmp;
    }

    // PJS (.psb): "digits,digits,\"text\"" — two integer time fields then a
    // quoted payload, no brackets/colons in the prefix.
    {
        size_t nl = head.find('\n');
        std::string_view first = trim(head.substr(0,
            nl == std::string_view::npos ? head.size() : nl));
        size_t c1 = first.find(',');
        if (c1 != std::string_view::npos && c1 > 0) {
            size_t c2 = first.find(',', c1 + 1);
            if (c2 != std::string_view::npos) {
                bool d1 = true, d2 = true;
                for (size_t k = 0; k < c1; ++k)
                    if (!(first[k] >= '0' && first[k] <= '9')) d1 = false;
                for (size_t k = c1 + 1; k < c2; ++k)
                    if (!(first[k] >= '0' && first[k] <= '9')) d2 = false;
                if (d1 && d2 && c2 + 1 < first.size())
                    return Format::Pjs;
            }
        }
    }
    return Format::Auto;
}

} // namespace

Format detectFormat(std::string_view content,
                    std::string_view fileName) noexcept {
    // Detection must run on normalized UTF-8: transcode UTF-16 BOM inputs
    // first, otherwise embedded NUL bytes defeat every text heuristic.
    std::string decoded;
    std::string_view view = content;
    if (content.size() >= 2) {
        unsigned char a = static_cast<unsigned char>(content[0]);
        unsigned char b = static_cast<unsigned char>(content[1]);
        bool be = (a == 0xFE && b == 0xFF);
        bool le = (a == 0xFF && b == 0xFE);
        if (le || be) {
            decoded.reserve(content.size() / 2);
            for (size_t k = 2; k + 1 < content.size(); k += 2) {
                unsigned lo = static_cast<unsigned char>(content[k]);
                unsigned hi = static_cast<unsigned char>(content[k + 1]);
                unsigned cp = le ? (hi << 8) | lo : (lo << 8) | hi;
                if (cp < 0x80) decoded.push_back(char(cp));
                else if (cp < 0x800) {
                    decoded.push_back(char(0xC0 | (cp >> 6)));
                    decoded.push_back(char(0x80 | (cp & 0x3F)));
                } else {
                    decoded.push_back(char(0xE0 | (cp >> 12)));
                    decoded.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
                    decoded.push_back(char(0x80 | (cp & 0x3F)));
                }
            }
            view = decoded;
        }
    }
    Format sniffed = sniffContent(view);
    if (sniffed != Format::Auto) return sniffed;
    return fromExtension(extensionOf(fileName));
}

namespace {

void dispatch(ParseContext& ctx, Format fmt, std::string_view raw) {
    switch (fmt) {
        case Format::Srt:      detail::parseSrt(ctx, raw); return;
        case Format::WebVtt:   detail::parseVtt(ctx, raw); return;
        case Format::Ass:      detail::parseAss(ctx, raw, false); return;
        case Format::Ssa:      detail::parseAss(ctx, raw, true); return;
        case Format::MicroDvd: detail::parseMicroDvd(ctx, raw); return;
        case Format::Sami:     detail::parseSami(ctx, raw); return;
        case Format::Pjs:      detail::parsePjs(ctx, raw); return;
        case Format::TedJson:  detail::parseTedJson(ctx, raw); return;
        case Format::Sbv:      detail::parseSbv(ctx, raw); return;
        case Format::Lrc:      detail::parseLrc(ctx, raw); return;
        case Format::Mpl2:     detail::parseMpl2(ctx, raw); return;
        case Format::Tmp:      detail::parseTmp(ctx, raw); return;
        default: return;
    }
}

} // namespace

ParseResult parse(const uint8_t* data, size_t size,
                  const ParserLimits& limits, const StylePolicy& policy,
                  Format forced) noexcept {
    ParseResult result;
    if (data == nullptr && size != 0) {
        result.diagnostics.push_back(
            {Severity::Fatal, 0, "input.null", "null data with non-zero size"});
        return result;
    }

    std::string_view raw(reinterpret_cast<const char*>(data), size);
    try {
        Format fmt = (forced != Format::Auto) ? forced
                                              : detectFormat(raw, {});
        if (fmt == Format::Auto || size_t(fmt) >= size_t(Format::Count_)) {
            result.diagnostics.push_back(
                {Severity::Fatal, 0, "format.unknown",
                 "could not determine subtitle format"});
            return result;
        }
        result.format = fmt;
        ParseContext ctx("parse", limits, policy, result);
        dispatch(ctx, fmt, raw);
        // Move the (same) result object back; ctx.result aliases `result`.
        return result;
    } catch (const FatalAbort& e) {
        result.diagnostics.push_back(
            {Severity::Fatal, 0, e.code(), "parse aborted by hard limit"});
        result.limitHit = true;
        return result;
    } catch (const std::bad_alloc&) {
        result.diagnostics.push_back(
            {Severity::Fatal, 0, "mem.alloc_failure",
             "memory allocation failed; returning partial result"});
        return result;
    } catch (const std::exception& e) {
        // Last-resort guard: a parser bug must still not crash the player.
        result.diagnostics.push_back(
            {Severity::Fatal, 0, "internal.exception", e.what()});
        return result;
    } catch (...) {
        result.diagnostics.push_back(
            {Severity::Fatal, 0, "internal.unknown",
             "unknown exception; returning partial result"});
        return result;
    }
}

} // namespace subsafe
