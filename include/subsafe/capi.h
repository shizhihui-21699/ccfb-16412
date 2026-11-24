// SPDX-License-Identifier: MIT
// Pure-C ABI wrapper. This is the recommended integration surface for players
// written in C or other languages. Every function is noexcept at the ABI
// boundary and all returned memory is owned by the caller via explicit free.
#ifndef SUBSAFE_CAPI_H
#define SUBSAFE_CAPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SUBSAFE_FMT_AUTO = 0,
    SUBSAFE_FMT_SRT,
    SUBSAFE_FMT_VTT,
    SUBSAFE_FMT_ASS,
    SUBSAFE_FMT_SSA,
    SUBSAFE_FMT_MICRODVD,
    SUBSAFE_FMT_SAMI,
    SUBSAFE_FMT_PJS,
    SUBSAFE_FMT_JSON,
    SUBSAFE_FMT_SBV,
    SUBSAFE_FMT_LRC,
    SUBSAFE_FMT_MPL2,
    SUBSAFE_FMT_TMP
} subsafe_format_t;

typedef enum {
    SUBSAFE_SEV_NOTE = 0,
    SUBSAFE_SEV_WARNING,
    SUBSAFE_SEV_ERROR,
    SUBSAFE_SEV_FATAL
} subsafe_severity_t;

typedef struct {
    int64_t start_ms;
    int64_t end_ms;
    const char* text;      // UTF-8, NUL-terminated; valid until result free
    int32_t pos_x;
    int32_t pos_y;
    int32_t layer;
    const char* style;
} subsafe_cue_t;

typedef struct {
    subsafe_severity_t severity;
    size_t line;
    const char* code;
    const char* message;
} subsafe_diagnostic_t;

typedef struct subsafe_result subsafe_result_t;

// Parse. Never returns NULL; an unparseable input yields an empty result with
// diagnostics. The input buffer is not retained after return.
subsafe_result_t* subsafe_parse(const uint8_t* data, size_t size,
                                subsafe_format_t forced,
                                int allow_embedded_fonts,
                                int allow_vector_drawing);

size_t subsafe_result_cue_count(const subsafe_result_t* r);
const subsafe_cue_t* subsafe_result_get_cue(const subsafe_result_t* r,
                                            size_t index);
size_t subsafe_result_diag_count(const subsafe_result_t* r);
const subsafe_diagnostic_t* subsafe_result_get_diag(const subsafe_result_t* r,
                                                    size_t index);
int subsafe_result_ok(const subsafe_result_t* r);
int subsafe_result_limit_hit(const subsafe_result_t* r);
subsafe_format_t subsafe_result_format(const subsafe_result_t* r);

// Free a result and every string it owns. Safe on NULL.
void subsafe_result_free(subsafe_result_t* r);

#ifdef __cplusplus
}
#endif

#endif // SUBSAFE_CAPI_H
