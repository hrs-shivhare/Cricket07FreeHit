#include "patch.h"
#include "reference.h"
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(void *) == 4, "Cricket07FreeHit requires x86");
_Static_assert(FH_PATCH_RVA == FH_ACTIVATION_RVA + 3, "Preserve native prologue");
_Static_assert(FH_PATCH_RVA + FH_PATCH_SIZE == 0x1956d5u, "Preserve native shared body");

static void message(FH_Log log, const char *text) { if (log) log(text); }

static BOOL accessible(const BYTE *p, size_t length, BOOL writable, BOOL executable) {
    uintptr_t at = (uintptr_t)p, end;
    if (!length || length > UINTPTR_MAX - at) return FALSE;
    end = at + length;
    while (at < end) {
        MEMORY_BASIC_INFORMATION m;
        DWORD protection;
        uintptr_t next;
        if (!VirtualQuery((const void *)at, &m, sizeof(m)) || m.State != MEM_COMMIT ||
            (m.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return FALSE;
        protection = m.Protect & 0xffu;
        if (executable && protection != PAGE_EXECUTE_READ &&
            protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY)
            return FALSE;
        if (writable) {
            if (protection != PAGE_READWRITE && protection != PAGE_WRITECOPY &&
                protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY)
                return FALSE;
        } else if (protection != PAGE_READONLY && protection != PAGE_READWRITE &&
                   protection != PAGE_WRITECOPY && protection != PAGE_EXECUTE_READ &&
                   protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY)
            return FALSE;
        next = (uintptr_t)m.BaseAddress + m.RegionSize;
        if (next <= at) return FALSE;
        at = next;
    }
    return TRUE;
}

BOOL FH_InspectImage(BYTE *base, FH_Image *out, FH_Log log) {
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS32 *pe;
    size_t header_end;
    if (!out) return FALSE;
    memset(out, 0, sizeof(*out));
    if (!base || !accessible(base, sizeof(*dos), FALSE, FALSE)) goto bad;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < (LONG)sizeof(*dos) ||
        dos->e_lfanew > 0x100000 || (uintptr_t)base > UINTPTR_MAX - (size_t)dos->e_lfanew) goto bad;
    if (!accessible(base + dos->e_lfanew, sizeof(*pe), FALSE, FALSE)) goto bad;
    pe = (IMAGE_NT_HEADERS32 *)(base + dos->e_lfanew);
    if (pe->Signature != IMAGE_NT_SIGNATURE || pe->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        pe->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        pe->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32) ||
        !pe->FileHeader.NumberOfSections || pe->FileHeader.NumberOfSections > 96 ||
        pe->OptionalHeader.ImageBase != FH_REFERENCE_BASE ||
        pe->OptionalHeader.SizeOfImage < FH_MATCH_RVA + FH_MATCH_SIZE ||
        pe->OptionalHeader.SizeOfImage > UINTPTR_MAX - (uintptr_t)base) goto bad;
    header_end = (size_t)dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) +
                 pe->FileHeader.SizeOfOptionalHeader +
                 (size_t)pe->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (header_end > pe->OptionalHeader.SizeOfHeaders ||
        pe->OptionalHeader.SizeOfHeaders > pe->OptionalHeader.SizeOfImage ||
        !accessible(base, header_end, FALSE, FALSE)) goto bad;
    out->base = base;
    out->size = pe->OptionalHeader.SizeOfImage;
    out->pe = pe;
    return TRUE;
bad:
    message(log, "WARNING: NOT APPLIED: unsupported or unreadable PE32/x86 image/layout (expected preferred base 0x00400000).");
    return FALSE;
}

static BOOL section_range(const FH_Image *image, uint32_t rva, size_t size, DWORD required) {
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(image->pe);
    uint64_t end = (uint64_t)rva + size;
    if (!size || end > image->size) return FALSE;
    for (unsigned i = 0; i < image->pe->FileHeader.NumberOfSections; ++i) {
        uint64_t start = sections[i].VirtualAddress;
        uint64_t span = sections[i].Misc.VirtualSize;
        if (span < sections[i].SizeOfRawData) span = sections[i].SizeOfRawData;
        if (rva >= start && end <= start + span &&
            (sections[i].Characteristics & required) == required)
            return accessible(image->base + rva, size, (required & IMAGE_SCN_MEM_WRITE) != 0,
                              (required & IMAGE_SCN_MEM_EXECUTE) != 0);
    }
    return FALSE;
}

static BOOL signature(const FH_Image *image, const FH_Signature *s, FH_Log log) {
    char line[240];
    if (!section_range(image, s->rva, s->size, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)) {
        snprintf(line, sizeof(line), "WARNING: NOT APPLIED: required routine '%s' at RVA 0x%08lx is absent/unreadable/non-executable.",
                 s->name, (unsigned long)s->rva);
        message(log, line);
        return FALSE;
    }
    for (size_t i = 0; i < s->size; ++i) {
        if (image->base[s->rva + i] != s->bytes[i]) {
            snprintf(line, sizeof(line), "WARNING: NOT APPLIED: required routine '%s' differs at RVA 0x%08lx: expected %02x, found %02x (different layout, modification or another hook).",
                     s->name, (unsigned long)(s->rva + i), s->bytes[i], image->base[s->rva + i]);
            message(log, line);
            return FALSE;
        }
    }
    snprintf(line, sizeof(line), "CHECK OK: %s, RVA 0x%08lx (%lu bytes).", s->name,
             (unsigned long)s->rva, (unsigned long)s->size);
    message(log, line);
    return TRUE;
}

BOOL FH_Validate(const FH_Image *image, FH_Log log) {
    BYTE getter[6] = {0xb8, 0, 0, 0, 0, 0xc3};
    uint32_t match_address;
    FH_Signature getter_signature = {"match-state getter", FH_MATCH_GETTER_RVA, getter, sizeof(getter)};
    if (!image || !image->base || !image->pe) return FALSE;
    match_address = (uint32_t)(uintptr_t)(image->base + FH_MATCH_RVA);
    memcpy(getter + 1, &match_address, 4);
    if (!signature(image, &getter_signature, log) ||
        !section_range(image, FH_MATCH_RVA, FH_MATCH_SIZE, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) {
        message(log, "WARNING: NOT APPLIED: native match storage/layout could not be validated.");
        return FALSE;
    }
    for (size_t i = 0; i < sizeof(fh_signatures) / sizeof(fh_signatures[0]); ++i)
        if (!signature(image, &fh_signatures[i], log)) return FALSE;
    return TRUE;
}

static void relative32(BYTE *out, uint32_t instruction, unsigned size, uint32_t target) {
    uint32_t displacement = target - (instruction + size);
    memcpy(out, &displacement, 4);
}

void FH_EncodePatch(BYTE out[FH_PATCH_SIZE]) {
    /* Native ESI already contains this. EAX/flags are overwritten by the
       untouched shared body. All targets are in the EXE, not in this DLL. */
    const BYTE compare[] = {0x66, 0x83, 0xb8, 0xc4, 0x58, 0x00, 0x00, 0x00};
    memset(out, 0x90, FH_PATCH_SIZE);
    out[0] = 0xe8; /* call match getter */
    relative32(out + 1, FH_PATCH_RVA, 5, FH_MATCH_GETTER_RVA);
    memcpy(out + 5, compare, sizeof(compare)); /* cmp word [eax+58C4],0 */
    out[13] = 0x0f; out[14] = 0x8e; /* jle native inactive path (signed) */
    relative32(out + 15, FH_PATCH_RVA + 13, 6, 0x195714u);
    out[19] = 0xe9; /* jmp native pending/no-ball/wide tests */
    relative32(out + 20, FH_PATCH_RVA + 19, 5, 0x1956d5u);
}

BOOL FH_Install(BYTE *base, FH_Log log) {
    FH_Image image;
    BYTE replacement[FH_PATCH_SIZE], original[FH_PATCH_SIZE];
    BYTE *destination;
    DWORD old_protection, ignored;
    if (!FH_InspectImage(base, &image, log) || !FH_Validate(&image, log)) return FALSE;
    destination = base + FH_PATCH_RVA;
    FH_EncodePatch(replacement);
    memcpy(original, destination, sizeof(original));
    if (!VirtualProtect(destination, FH_PATCH_SIZE, PAGE_EXECUTE_READWRITE, &old_protection)) {
        message(log, "WARNING: NOT APPLIED: cannot make the eligibility block writable; no code changed.");
        return FALSE;
    }
    /* Detect an overlapping startup patch before changing instructions. */
    if (memcmp(base + FH_ACTIVATION_RVA, fh_activation, sizeof(fh_activation))) {
        if (!VirtualProtect(destination, FH_PATCH_SIZE, old_protection, &ignored))
            message(log, "WARNING: page-protection restoration failed after a signature conflict.");
        message(log, "WARNING: NOT APPLIED: activation routine changed during initialization.");
        return FALSE;
    }
    memcpy(destination, replacement, sizeof(replacement));
    if (!FlushInstructionCache(GetCurrentProcess(), destination, FH_PATCH_SIZE)) goto rollback;
    if (!VirtualProtect(destination, FH_PATCH_SIZE, old_protection, &ignored)) goto rollback;
    message(log, "APPLIED: native free-hit tournament whitelist replaced with signed match over-limit > 0 (RVA 0x001956a3, 50 bytes).");
    message(log, "Native pending state, current no-ball/wide tests, dismissal checks, no-ball penalties and tournament identity retained. Test/unlimited (-1), zero and negative over limits are ineligible.");
    return TRUE;
rollback:
    memcpy(destination, original, sizeof(original));
    if (!FlushInstructionCache(GetCurrentProcess(), destination, FH_PATCH_SIZE))
        message(log, "WARNING: instruction-cache flush failed while restoring original code.");
    if (!VirtualProtect(destination, FH_PATCH_SIZE, old_protection, &ignored))
        message(log, "WARNING: page-protection restoration failed while restoring original code.");
    message(log, "WARNING: NOT APPLIED: patch finalization failed; original eligibility bytes restored.");
    return FALSE;
}
