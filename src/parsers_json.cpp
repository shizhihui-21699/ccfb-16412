// SPDX-License-Identifier: MIT
// Minimal, hardened JSON subset parser for TED-style timed text.
//
// No third-party JSON library is pulled in: the attack surface is kept to a
// single recursive-descent reader with an explicit depth counter, a hard cap
// on parsed values, and no allocation sized from file integers. Only the
// subset needed for cues (objects, arrays, strings, numbers, booleans) is
// supported; anything else yields a diagnostic and a clean failure.
#include "internal/parsers.h"

#include <initializer_list>
#include <utility>

namespace subsafe::detail {

namespace {

class MiniJson {
public:
    MiniJson(ParseContext& ctx, std::string_view s) : ctx_(ctx), s_(s) {}

    // Value variant, kept deliberately small.
    enum class Kind { Null, Bool, Num, Str, Arr, Obj };
    struct Value {
        Kind kind = Kind::Null;
        bool boolean = false;
        double number = 0.0;
        std::string str;                       // decoded string content
        std::vector<Value> arr;
        std::vector<std::pair<std::string, Value>> obj;
    };

    bool parse(Value& root) {
        skipWs();
        if (!parseValue(root, 0)) return false;
        skipWs();
        return pos_ == s_.size();   // trailing junk => reject
    }

private:
    ParseContext& ctx_;
    std::string_view s_;
    size_t pos_ = 0;
    size_t valueCount_ = 0;
    static constexpr size_t kMaxValues = 500'000;

    void skipWs() {
        while (pos_ < s_.size() &&
               (s_[pos_] == ' ' || s_[pos_] == '\t' ||
                s_[pos_] == '\n' || s_[pos_] == '\r'))
            ++pos_;
    }

    bool parseValue(Value& v, unsigned depth) {
        if (depth > ctx_.lim.maxDepth) {
            ctx_.diag.error(0, "json.depth", "nesting exceeds maxDepth");
            return false;
        }
        if (++valueCount_ > kMaxValues) {
            ctx_.diag.error(0, "json.value_limit", "too many JSON values");
            ctx_.markLimit();
            return false;
        }
        skipWs();
        if (pos_ >= s_.size()) return false;
        char c = s_[pos_];
        if (c == '{') return parseObject(v, depth);
        if (c == '[') return parseArray(v, depth);
        if (c == '"') { v.kind = Kind::Str; return parseString(v.str); }
        if (c == 't' || c == 'f') return parseBool(v);
        if (c == 'n') return parseNull(v);
        if (c == '-' || (c >= '0' && c <= '9')) return parseNumber(v);
        return false;
    }

    bool parseObject(Value& v, unsigned depth) {
        v.kind = Kind::Obj;
        ++pos_;   // '{'
        skipWs();
        if (pos_ < s_.size() && s_[pos_] == '}') { ++pos_; return true; }
        while (pos_ < s_.size()) {
            skipWs();
            if (pos_ >= s_.size() || s_[pos_] != '"') return false;
            std::string key;
            if (!parseString(key)) return false;
            if (v.obj.size() >= 1024) {
                ctx_.diag.error(0, "json.object_limit", "object too wide");
                return false;
            }
            skipWs();
            if (pos_ >= s_.size() || s_[pos_] != ':') return false;
            ++pos_;
            Value child;
            if (!parseValue(child, depth + 1)) return false;
            v.obj.emplace_back(std::move(key), std::move(child));
            skipWs();
            if (pos_ >= s_.size()) return false;
            if (s_[pos_] == ',') { ++pos_; continue; }
            if (s_[pos_] == '}') { ++pos_; return true; }
            return false;
        }
        return false;
    }

    bool parseArray(Value& v, unsigned depth) {
        v.kind = Kind::Arr;
        ++pos_;   // '['
        skipWs();
        if (pos_ < s_.size() && s_[pos_] == ']') { ++pos_; return true; }
        while (pos_ < s_.size()) {
            Value child;
            if (!parseValue(child, depth + 1)) return false;
            v.arr.push_back(std::move(child));
            if (v.arr.size() > ctx_.lim.maxCues) {
                ctx_.diag.error(0, "json.array_limit", "array exceeds maxCues");
                ctx_.markLimit();
                return false;
            }
            skipWs();
            if (pos_ >= s_.size()) return false;
            if (s_[pos_] == ',') { ++pos_; continue; }
            if (s_[pos_] == ']') { ++pos_; return true; }
            return false;
        }
        return false;
    }

    bool parseString(std::string& out) {
        if (s_[pos_] != '"') return false;
        ++pos_;
        while (pos_ < s_.size()) {
            char c = s_[pos_++];
            if (c == '"') return true;
            if (c == '\\') {
                if (pos_ >= s_.size()) return false;
                char e = s_[pos_++];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        if (pos_ + 4 > s_.size()) return false;
                        unsigned cp = 0;
                        for (int k = 0; k < 4; ++k) {
                            int h = hexVal(s_[pos_++]);
                            if (h < 0) return false;
                            cp = cp * 16 + unsigned(h);
                        }
                        appendCp(out, cp);
                        break;
                    }
                    default: return false;   // unknown escape -> reject
                }
            } else {
                out.push_back(c);
            }
            if (out.size() > ctx_.lim.maxCueTextBytes) {
                out.resize(ctx_.lim.maxCueTextBytes);
                ctx_.markLimit();
            }
        }
        return false;
    }

    static int hexVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // Encode a Unicode code point as UTF-8; surrogates become U+FFFD.
    void appendCp(std::string& out, unsigned cp) {
        if (cp >= 0xD800 && cp <= 0xDFFF) cp = 0xFFFD;
        if (cp < 0x80) out.push_back(char(cp));
        else if (cp < 0x800) {
            out.push_back(char(0xC0 | (cp >> 6)));
            out.push_back(char(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(char(0xE0 | (cp >> 12)));
            out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(char(0x80 | (cp & 0x3F)));
        } else if (cp <= 0x10FFFF) {
            out.push_back(char(0xF0 | (cp >> 18)));
            out.push_back(char(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(char(0x80 | (cp & 0x3F)));
        }
    }

    bool parseNumber(Value& v) {
        size_t start = pos_;
        if (s_[pos_] == '-') ++pos_;
        bool any = false;
        while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') {
            any = true; ++pos_;
        }
        if (pos_ < s_.size() && s_[pos_] == '.') {
            ++pos_;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') {
                any = true; ++pos_;
            }
        }
        if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
            bool expAny = false;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') {
                expAny = true; ++pos_;
            }
            if (!expAny) return false;
        }
        if (!any) return false;
        double d = 0.0;
        if (!parseBoundedDouble(s_.substr(start, pos_ - start), d))
            return false;
        v.kind = Kind::Num;
        v.number = d;
        return true;
    }

    bool parseBool(Value& v) {
        if (s_.compare(pos_, 4, "true") == 0) {
            pos_ += 4; v.kind = Kind::Bool; v.boolean = true; return true;
        }
        if (s_.compare(pos_, 5, "false") == 0) {
            pos_ += 5; v.kind = Kind::Bool; v.boolean = false; return true;
        }
        return false;
    }

    bool parseNull(Value& v) {
        if (s_.compare(pos_, 4, "null") == 0) {
            pos_ += 4; v.kind = Kind::Null; return true;
        }
        return false;
    }
};

const MiniJson::Value* findKey(const MiniJson::Value& obj,
                               std::string_view key) {
    if (obj.kind != MiniJson::Kind::Obj) return nullptr;
    for (const auto& kv : obj.obj)
        if (kv.first == key) return &kv.second;
    return nullptr;
}

// Return the first present key among candidates, or nullptr.
const MiniJson::Value* findAnyKey(const MiniJson::Value& obj,
                                  std::initializer_list<const char*> keys) {
    for (const char* k : keys) {
        if (const MiniJson::Value* v = findKey(obj, k)) return v;
    }
    return nullptr;
}

} // namespace

void parseTedJson(ParseContext& ctx, std::string_view raw) {
    // BOM/whitespace tolerant; the reader handles BOM, but JSON starts after
    // optional surrounding whitespace only.
    MiniJson reader(ctx, raw);
    MiniJson::Value root;
    if (!reader.parse(root)) {
        ctx.diag.error(0, "json.malformed", "not a supported JSON subtitle");
        return;
    }

    // Accept either { "captions": [ {start, dur, content}, ... ] } (TED) or
    // a bare array of cue objects, or { "cues": [...] }.
    const MiniJson::Value* arr = nullptr;
    if (root.kind == MiniJson::Kind::Arr) arr = &root;
    else if (root.kind == MiniJson::Kind::Obj) {
        arr = findKey(root, "captions");
        if (!arr || arr->kind != MiniJson::Kind::Arr)
            arr = findKey(root, "cues");
    }
    if (!arr || arr->kind != MiniJson::Kind::Arr) {
        ctx.diag.error(0, "json.schema", "no caption array found");
        return;
    }

    for (const auto& item : arr->arr) {
        if (item.kind != MiniJson::Kind::Obj) continue;
        const MiniJson::Value* jStart = findAnyKey(item, {"startTime", "start"});
        const MiniJson::Value* jDur   = findAnyKey(item, {"duration", "dur"});
        const MiniJson::Value* jText  = findAnyKey(item, {"content", "text"});
        if (!jStart || jStart->kind != MiniJson::Kind::Num) {
            ++ctx.result.droppedCues;
            continue;
        }
        Cue cue;
        double startSec = jStart->number;
        if (startSec < 0) startSec = 0;
        cue.startMs = clampTime(int64_t(startSec * 1000.0), ctx.lim);
        double durSec = (jDur && jDur->kind == MiniJson::Kind::Num &&
                         jDur->number > 0)
                            ? jDur->number : 3.0;
        if (durSec > double(ctx.lim.maxCueDurationMs) / 1000.0)
            durSec = double(ctx.lim.maxCueDurationMs) / 1000.0;
        cue.endMs = clampTime(cue.startMs + int64_t(durSec * 1000.0), ctx.lim);
        if (jText)
            cue.text = (jText->kind == MiniJson::Kind::Str) ? jText->str : "";

        finishCueText(ctx, cue, InlineTagMode::HtmlInline, nullptr);
        normalizeRange(ctx, 0, cue);
        if (!cue.empty()) ctx.addCue(std::move(cue));
    }
}

} // namespace subsafe::detail
