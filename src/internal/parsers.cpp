// SPDX-License-Identifier: MIT
#include "internal/parsers.h"

#include "subsafe/style_policy.h"

namespace subsafe::detail {

namespace {

// Process ASS/SSA cue text: keep plain runs, run every balanced {...}
// override block through the style sandbox. Unbalanced braces are stripped
// rather than echoed (a renderer that treats them as markup is exactly what
// we must not feed ambiguous input to). Drawing-mode payloads (\p) have their
// command budget enforced here.
std::string sanitizeAssText(ParseContext& ctx, std::string_view text) {
    std::string out;
    TagAudit audit;
    size_t i = 0;
    size_t totalDrawing = 0;

    while (i < text.size()) {
        char c = text[i];
        if (c != '{') {
            ctx.appendCapped(out, std::string_view(&text[i], 1),
                             ctx.lim.maxCueTextBytes);
            ++i;
            continue;
        }
        size_t close = text.find('}', i + 1);
        if (close == std::string_view::npos) {
            ctx.diag.warning(0, "ass.unbalanced_brace",
                             "unbalanced override brace dropped");
            break;   // tail is inert; do not echo the stray '{'
        }
        std::string_view block = text.substr(i + 1, close - i - 1);
        TagAudit blockAudit;
        std::string clean = sanitizeAssBlock(block, ctx.policy, blockAudit);
        if (blockAudit.drawingCommands > 0) {
            totalDrawing += blockAudit.drawingCommands;
            if (totalDrawing > ctx.lim.maxDrawingCommands) {
                ctx.diag.warning(0, "ass.drawing_budget",
                                 "drawing command budget exceeded; block cut");
                ctx.markLimit();
                break;
            }
        }
        audit.strippedAny = audit.strippedAny || blockAudit.strippedAny;
        audit.clampedAny = audit.clampedAny || blockAudit.clampedAny;
        if (!clean.empty()) {
            out.push_back('{');
            ctx.appendCapped(out, clean, ctx.lim.maxCueTextBytes);
            out.push_back('}');
        }
        i = close + 1;
    }
    return out;
}

} // namespace

void finishCueText(ParseContext& ctx, Cue& cue, InlineTagMode mode,
                   TagAudit* auditOut) {
    // 1) Remove NUL / C1 control characters before anything else.
    std::string stage1 = stripControlChars(cue.text);
    // 2) Repair invalid UTF-8 (and drop embedded NULs) under the budget.
    std::string stage2 = sanitizeUtf8(ctx, stage1);

    TagAudit audit;
    std::string stage3;
    switch (mode) {
        case InlineTagMode::AssOverride:
            stage3 = sanitizeAssText(ctx, stage2);
            break;
        case InlineTagMode::HtmlInline:
            stage3 = sanitizeHtmlInline(stage2, ctx.policy, audit);
            break;
        case InlineTagMode::Plain:
            stage3 = std::move(stage2);
            break;
    }

    // Hard per-cue length guarantee regardless of accumulated growth.
    if (stage3.size() > ctx.lim.maxCueTextBytes) {
        stage3.resize(ctx.lim.maxCueTextBytes);
        ctx.markLimit();
    }
    cue.text = std::move(stage3);
    if (auditOut) *auditOut = audit;
}

void normalizeRange(ParseContext& ctx, size_t lineNo, Cue& cue) {
    cue.startMs = clampTime(cue.startMs, ctx.lim);
    cue.endMs   = clampTime(cue.endMs, ctx.lim);
    if (cue.endMs < cue.startMs) {
        ctx.diag.warning(lineNo, "time.reversed",
                         "cue end before start; timestamps swapped");
        std::swap(cue.startMs, cue.endMs);
    }
    int64_t dur = cue.endMs - cue.startMs;
    if (dur > ctx.lim.maxCueDurationMs) {
        ctx.diag.warning(lineNo, "time.duration",
                         "cue duration exceeds maxCueDurationMs; end clamped");
        cue.endMs = clampTime(cue.startMs + ctx.lim.maxCueDurationMs, ctx.lim);
        ctx.markLimit();
    }
}

} // namespace subsafe::detail
