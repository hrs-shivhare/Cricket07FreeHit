#ifndef C07_FREE_HIT_PATCH_H
#define C07_FREE_HIT_PATCH_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#define FH_REFERENCE_BASE 0x400000u
#define FH_ACTIVATION_RVA 0x1956a0u
#define FH_PATCH_RVA 0x1956a3u
#define FH_PATCH_SIZE 50u
#define FH_MATCH_GETTER_RVA 0x0ec220u
#define FH_MATCH_RVA 0x5a48b0u
#define FH_MATCH_SIZE 0x21261u
#define FH_OVER_LIMIT_OFFSET 0x58c4u
#define FH_FLAGS_OFFSET 0x21218u
#define FH_PENDING_OFFSET 0x21260u
#define FH_ACTIVE_OFFSET 0xfcu

typedef void (*FH_Log)(const char *line);
typedef struct FH_Image {
    BYTE *base;
    size_t size;
    IMAGE_NT_HEADERS32 *pe;
} FH_Image;

/* No writes on failed validation. Image size and file hash are not allowlists. */
BOOL FH_InspectImage(BYTE *base, FH_Image *out, FH_Log log);
BOOL FH_Validate(const FH_Image *image, FH_Log log);
BOOL FH_Install(BYTE *base, FH_Log log);
void FH_EncodePatch(BYTE out[FH_PATCH_SIZE]);

#endif
