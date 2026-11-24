// SPDX-License-Identifier: MIT
#include "subsafe/style_policy.h"

#include <array>
#include <cctype>
#include <cstring>
#include <string>

namespace subsafe {

namespace {

bool isAsciiAlpha(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
bool isAsciiDigit(char c) noexcept { return c >= '0' && c <= '9'; }
char lowerAscii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c;
}

int32_t clampI(int64_t v, int32_t lo, int32_t hi) noexcept {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return static_cast<int32_t>(v);
}

bool readInt(std::string_view s, size_t& i, int64_t& out) noexcept {
    size_t start = i;
    bool neg = false;
    if (i < s.size() && (s[i] == '-' || s[i] == '+')) { neg = s[i] == '-'; ++i; }
    uint64_t mag = 0;
    bool any = false;
    while (i < s.size() && isAsciiDigit(s[i])) {
        any = true;
        if (mag < UINT64_MAX / 10) mag = mag * 10 + uint64_t(s[i] - '0');
        ++i;
    }
    if (!any) { i = start; return false; }
    if (mag > uint64_t(INT64_MAX)) mag = uint64_t(INT64_MAX);
    out = neg ? -static_cast<int64_t>(mag) : static_cast<int64_t>(mag);
    return true;
}

void appendInt(std::string& dst, int32_t v) {
    char buf[16];
    int n = std::snprintf(buf, sizeof(buf), "%d", v);
    if (n > 0) dst.append(buf, static_cast<size_t>(n));
}

bool isGeometryTag(std::string_view name) noexcept {
    return name == "pos" || name == "org";
}
bool isFontSizeTag(std::string_view name) noexcept {
    return name == "fs" || name == "fscx" || name == "fscy";
}
bool isScalarEffectTag(std::string_view name) noexcept {
    return name == "bord" || name == "shad" || name == "be" || name == "blur" ||
           name == "fad" || name == "fade" || name == "frx" || name == "fry" ||
           name == "frz" || name == "fr" || name == "fax" || name == "fay" ||
           name == "xbord" || name == "ybord" || name == "xshad" ||
           name == "yshad";
}
bool isKaraokeTag(std::string_view name) noexcept {
    return name == "k" || name == "kf" || name == "ko" || name == "K";
}
bool isPassthroughTag(std::string_view name) noexcept {
    static const char* kAllowed[] = {
        "b", "i", "u", "s", "bo", "it", "ul", "strikeout",
        "an", "a", "q", "r", "fn", "alpha", "1a", "2a", "3a", "4a",
        "c", "1c", "2c", "3c", "4c", "pbo", "fe",
    };
    for (const char* t : kAllowed)
        if (name == t) return true;
    return false;
}

} // namespace

std::string sanitizeAssBlock(std::string_view block,
                             const StylePolicy& policy,
                             TagAudit& audit) {
    std::string out;
    out.reserve(std::min(block.size(), policy.maxTagBytes) + 1);

    size_t i = 0;
    while (i < block.size()) {
        if (out.size() >= policy.maxTagBytes) { audit.strippedAny = true; break; }
        if (block[i] != '\\') { out.push_back(block[i]); ++i; continue; }

        size_t nameStart = i + 1;
        size_t j = nameStart;
        if (j < block.size() && isAsciiDigit(block[j])) ++j;
        while (j < block.size() && isAsciiAlpha(block[j])) ++j;
        std::string_view name = block.substr(nameStart, j - nameStart);
        i = j;

        if (name.empty()) {
            if (i < block.size() && (block[i] == 'n' || block[i] == 'N' ||
                                     block[i] == 'h')) {
                if (policy.allowWrapHints) { out.push_back('\\'); out.push_back(block[i]); }
                else audit.strippedAny = true;
                ++i;
            } else {
                audit.strippedAny = true;
                if (i < block.size()) ++i;
            }
            continue;
        }

        std::string_view arg;
        bool hasParen = (i < block.size() && block[i] == '(');
        if (hasParen) {
            // Scan from the char after the opening '(' with depth starting at
            // 1. The length guard runs only on inner chars so a balanced pair
            // can never be misclassified as malformed.
            size_t depth = 1;
            size_t argStart = i + 1;
            size_t k = argStart;
            for (; k < block.size(); ++k) {
                if (block[k] == '(') ++depth;
                else if (block[k] == ')') {
                    if (--depth == 0) break;
                }
                if (k - argStart >= policy.maxTagBytes) {
                    k = block.size();
                    break;
                }
            }
            if (k >= block.size() || depth != 0) {
                audit.strippedAny = true;
                i = block.size();
                break;
            }
            arg = block.substr(argStart, k - argStart);
            i = k + 1;
        }

        if (name == "move") {
            if (policy.allowMove) {
                out += "\\move(";
                size_t p = 0;
                bool first = true;
                int count = 0;
                while (p < arg.size() && count < 4) {
                    while (p < arg.size() && (arg[p] == ' ' || arg[p] == ',')) ++p;
                    int64_t v = 0;
                    if (readInt(arg, p, v)) {
                        if (!first) out.push_back(',');
                        appendInt(out, clampI(v, -policy.maxCoordPx,
                                              policy.maxCoordPx));
                        first = false; ++count; audit.clampedAny = true;
                    } else { ++p; }
                }
                out.push_back(')');
            } else audit.strippedAny = true;
            continue;
        }
        if (name == "t") {
            if (policy.allowAnimatedTransform) {
                out += "\\t(";
                out.append(arg.data(), std::min(arg.size(), policy.maxTagBytes));
                out.push_back(')');
            } else audit.strippedAny = true;
            continue;
        }
        if (name == "p") {
            if (policy.allowVectorDrawing) {
                out += "\\p";
                int64_t mode = 0; size_t p = 0;
                std::string_view src = hasParen ? arg : block.substr(j);
                if (readInt(src, p, mode)) {
                    if (mode > 0)
                        audit.drawingCommands += static_cast<size_t>(mode);
                    appendInt(out, clampI(mode, 0, 1));
                    if (!hasParen) i = j + p;
                }
            } else audit.strippedAny = true;
            continue;
        }
        if (isGeometryTag(name)) {
            out += "\\"; out.append(name.data(), name.size()); out.push_back('(');
            size_t p = 0; bool first = true;
            while (p < arg.size()) {
                while (p < arg.size() && (arg[p] == ' ' || arg[p] == ',')) ++p;
                int64_t v = 0;
                if (readInt(arg, p, v)) {
                    if (!first) out.push_back(',');
                    appendInt(out, clampI(v, -policy.maxCoordPx,
                                          policy.maxCoordPx));
                    first = false; audit.clampedAny = true;
                } else { if (p < arg.size()) ++p; }
            }
            out.push_back(')');
            continue;
        }
        if (isFontSizeTag(name)) {
            out += "\\"; out.append(name.data(), name.size());
            int64_t v = 0; size_t p = 0;
            std::string_view src = hasParen ? arg : block.substr(j);
            if (readInt(src, p, v)) {
                appendInt(out, clampI(v, policy.minFontSize,
                                      policy.maxFontSize));
                audit.clampedAny = true;
                if (!hasParen) i = j + p;
            }
            continue;
        }
        if (isScalarEffectTag(name)) {
            out += "\\"; out.append(name.data(), name.size());
            if (hasParen) {
                out.push_back('(');
                size_t p = 0; bool first = true;
                while (p < arg.size()) {
                    while (p < arg.size() && (arg[p] == ' ' || arg[p] == ',')) ++p;
                    int64_t v = 0;
                    if (readInt(arg, p, v)) {
                        if (!first) out.push_back(',');
                        int32_t cap = (name == "blur" || name == "be")
                                          ? policy.maxEffectRadiusPx
                                          : policy.maxCoordPx;
                        appendInt(out, clampI(v, 0, cap));
                        first = false; audit.clampedAny = true;
                    } else { if (p < arg.size()) ++p; }
                }
                out.push_back(')');
            }
            continue;
        }
        if (isKaraokeTag(name)) {
            if (policy.allowKaraoke) {
                out += "\\"; out.append(name.data(), name.size());
                int64_t v = 0; size_t p = 0;
                std::string_view src = hasParen ? arg : block.substr(j);
                if (readInt(src, p, v)) {
                    appendInt(out, clampI(v, 0, 8640000));
                    audit.clampedAny = true;
                    if (!hasParen) i = j + p;
                }
            } else audit.strippedAny = true;
            continue;
        }
        if (isPassthroughTag(name)) {
            if (!policy.preserveInlineStyles &&
                !(name == "an" || name == "a" || name == "q")) {
                audit.strippedAny = true;
                continue;
            }
            out += "\\"; out.append(name.data(), name.size());
            if (hasParen) {
                out.push_back('(');
                size_t safe = std::min(arg.size(), policy.maxTagBytes);
                for (size_t k = 0; k < safe; ++k) {
                    char c = arg[k];
                    if (c == '{' || c == '}') { audit.strippedAny = true; continue; }
                    out.push_back(c);
                }
                out.push_back(')');
            }
            continue;
        }
        audit.strippedAny = true;   // unknown tag: default-deny
    }

    if (audit.strippedAny && policy.markStripped) out += "[stripped]";
    return out;
}

// ---------------------------------------------------------------------------
// HTML-ish inline sanitizer (SRT / VTT / SAMI)
// ---------------------------------------------------------------------------
namespace {

constexpr size_t kNameCap = 32;     // element/attribute name cap
constexpr size_t kAttrCap = 256;    // single attribute value cap

bool isAllowedInlineTag(std::string_view name, bool closing) noexcept {
    // `name` has the leading slash removed (closing is a separate flag), so
    // both open and close use the same bare element-name table.
    static const char* kAllowed[] = {"b", "i", "u", "s", "em", "strong",
                                     "ruby", "rt", "br", "font"};
    (void)closing;
    for (const char* t : kAllowed)
        if (name == t) return true;
    return false;
}

bool isDroppedElement(std::string_view name) noexcept {
    return name == "script" || name == "style" || name == "object" ||
           name == "embed" || name == "iframe" || name == "svg" ||
           name == "xml" || name == "noscript";
}

// Case-insensitive compare of `a` against NUL-terminated `b`.
bool ieq(std::string_view a, const char* b) noexcept {
    size_t n = std::strlen(b);
    if (a.size() != n) return false;
    for (size_t k = 0; k < n; ++k)
        if (lowerAscii(a[k]) != b[k]) return false;
    return true;
}

// Local case-insensitive prefix check (this TU does not include the internal
// common header, so it stays self-contained).
bool iStartsWith(std::string_view s, const char* prefix) noexcept {
    size_t n = std::strlen(prefix);
    if (s.size() < n) return false;
    for (size_t k = 0; k < n; ++k)
        if (lowerAscii(s[k]) != prefix[k]) return false;
    return true;
}

// Read one tag starting at text[pos]=='<'. Returns index just past '>'.
// Emits a sanitized tag (or nothing) into out.
size_t processTag(std::string_view text, size_t pos, const StylePolicy& policy,
                  TagAudit& audit, std::string& out, bool& skipBody,
                  std::string& skipName) {
    size_t close = text.find('>', pos + 1);
    if (close == std::string_view::npos) {
        audit.strippedAny = true;
        return text.size();   // unterminated: rest is inert text
    }
    std::string_view inner = text.substr(pos + 1, close - pos - 1);
    size_t p = 0;
    while (p < inner.size() && (inner[p] == ' ' || inner[p] == '\t'))
        ++p;
    bool closing = false;
    if (p < inner.size() && inner[p] == '/') { closing = true; ++p; }

    char nameBuf[kNameCap];
    size_t nameLen = 0;
    while (p < inner.size() && inner[p] != ' ' && inner[p] != '\t' &&
           inner[p] != '/' && inner[p] != '>' && nameLen < kNameCap)
        nameBuf[nameLen++] = lowerAscii(inner[p++]);
    std::string_view name(nameBuf, nameLen);

    // Element whose entire body must be skipped.
    if (!closing && isDroppedElement(name)) {
        audit.strippedAny = true;
        skipBody = true;
        skipName.assign(name.data(), name.size());
        return close + 1;
    }
    if (closing && !skipName.empty() && name == skipName) {
        skipBody = false;
        skipName.clear();
        return close + 1;
    }
    if (skipBody) return close + 1;   // stay inside skipped element

    if (!isAllowedInlineTag(name, closing)) {
        audit.strippedAny = true;     // drop tag, keep inner text
        return close + 1;
    }

    // Rebuild an allowed tag. Only <font> carries attributes, and only a
    // fixed whitelist of them; every value is length-capped and stripped of
    // quote/bracket characters, so javascript: / on*= can't survive.
    std::string rebuilt = closing ? "</" : "<";
    rebuilt.append(name.data(), name.size());

    if (!closing && name == "font") {
        while (p < inner.size()) {
            while (p < inner.size() &&
                   (inner[p] == ' ' || inner[p] == '\t' || inner[p] == '/'))
                ++p;
            if (p >= inner.size()) break;
            char anBuf[kNameCap];
            size_t anLen = 0;
            while (p < inner.size() && inner[p] != '=' && inner[p] != ' ' &&
                   inner[p] != '\t' && inner[p] != '>' && anLen < kNameCap)
                anBuf[anLen++] = lowerAscii(inner[p++]);
            std::string_view an(anBuf, anLen);
            if (p >= inner.size() || inner[p] != '=') {
                // Bare token: skip to next whitespace.
                while (p < inner.size() && inner[p] != ' ' &&
                       inner[p] != '\t')
                    ++p;
                continue;
            }
            ++p;   // '='
            char quote = 0;
            if (p < inner.size() && (inner[p] == '"' || inner[p] == '\'')) {
                quote = inner[p]; ++p;
            }
            std::string value;
            while (p < inner.size() && value.size() < kAttrCap) {
                char c = inner[p];
                if (quote != 0 && c == quote) { ++p; break; }
                if (quote == 0 && (c == ' ' || c == '\t' || c == '>')) break;
                if (c == '<' || c == '>' || c == '"' || c == '\'') {
                    audit.strippedAny = true;
                } else {
                    value.push_back(c);
                }
                ++p;
            }
            // Advance past an unquoted value's terminator.
            while (p < inner.size() && inner[p] != ' ' &&
                   inner[p] != '\t' && inner[p] != '>')
                ++p;

            bool okAttr = ieq(an, "color") || ieq(an, "size") ||
                          ieq(an, "face");
            if (!okAttr) { audit.strippedAny = true; continue; }
            // Reject any value that introduces a URL/script scheme.
            if (iStartsWith(value, "javascript:") ||
                iStartsWith(value, "vbscript:") ||
                iStartsWith(value, "data:")) {
                audit.strippedAny = true;
                continue;
            }
            rebuilt += " ";
            rebuilt.append(an.data(), an.size());
            rebuilt += "=\"";
            rebuilt += value;
            rebuilt.push_back('"');
        }
    }
    rebuilt.push_back('>');
    if (out.size() + rebuilt.size() <= policy.maxTagBytes * 16)
        out += rebuilt;
    else
        audit.strippedAny = true;
    return close + 1;
}

} // namespace

std::string sanitizeHtmlInline(std::string_view text,
                               const StylePolicy& policy,
                               TagAudit& audit) {
    std::string out;
    out.reserve(std::min(text.size(), size_t(4096)));
    bool skipBody = false;
    std::string skipName;

    for (size_t i = 0; i < text.size();) {
        if (text[i] == '<') {
            i = processTag(text, i, policy, audit, out, skipBody, skipName);
            continue;
        }
        if (!skipBody) {
            if (out.size() < policy.maxTagBytes * 16)
                out.push_back(text[i]);
            else
                audit.strippedAny = true;
        }
        ++i;
    }
    if (skipBody) audit.strippedAny = true;   // unclosed dropped element
    return out;
}

std::string stripControlChars(std::string_view text) {
    std::string out;
    out.reserve(std::min(text.size(), size_t(4096)));
    for (size_t i = 0; i < text.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        if (c < 0x20) {
            if (c == '\t' || c == '\n' || c == '\r') out.push_back(text[i]);
            continue;   // drop NUL and other C0 controls
        }
        if (c >= 0x7F && c <= 0x9F && c != 0x85) continue;  // drop C1
        out.push_back(text[i]);
    }
    return out;
}

} // namespace subsafe
