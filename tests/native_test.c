#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../src/patch.h"
#include "../src/reference.h"

typedef void (__attribute__((thiscall)) *Activation)(BYTE *manager);
static unsigned checks, cases, warnings;
static int failures;
static char last_log[512];

static void check(int ok, const char *name) {
    ++checks;
    if (!ok) { ++failures; fprintf(stderr, "FAIL: %s\n", name); }
}
static void capture(const char *line) {
    snprintf(last_log, sizeof(last_log), "%s", line);
    if (strstr(line, "WARNING")) ++warnings;
}
static void put16(BYTE *p, int value) { int16_t v = (int16_t)value; memcpy(p, &v, 2); }
static void put32(BYTE *p, uint32_t value) { memcpy(p, &value, 4); }

/* Map the actual file into a private test allocation. Never launch or rewrite
   the game. Rebase only the two getters executed by this bounded fixture. */
static BYTE *load_image(const char *path, size_t *image_size, BOOL *oracle_available) {
    FILE *file = fopen(path, "rb");
    BYTE *disk = NULL, *image = NULL;
    long length;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS32 *pe;
    IMAGE_SECTION_HEADER *sections;
    const BYTE match_getter[] = {0xb8, 0xb0, 0x48, 0x9a, 0x00, 0xc3};
    const BYTE tournament_getter[] = {0xa1, 0xe0, 0x0e, 0x93, 0x00, 0xc3};
    *oracle_available = FALSE;
    if (!file) return NULL;
    if (fseek(file, 0, SEEK_END) || (length = ftell(file)) < 64 || fseek(file, 0, SEEK_SET)) goto done;
    disk = malloc((size_t)length);
    if (!disk || fread(disk, 1, (size_t)length, file) != (size_t)length) goto done;
    dos = (IMAGE_DOS_HEADER *)disk;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        (size_t)dos->e_lfanew + sizeof(*pe) > (size_t)length) goto done;
    pe = (IMAGE_NT_HEADERS32 *)(disk + dos->e_lfanew);
    if (pe->Signature != IMAGE_NT_SIGNATURE || pe->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        pe->OptionalHeader.SizeOfHeaders > (size_t)length) goto done;
    *image_size = pe->OptionalHeader.SizeOfImage;
    image = VirtualAlloc(NULL, ((*image_size + 0xfff) & ~(size_t)0xfff) + 0x10000,
                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!image) goto done;
    memcpy(image, disk, pe->OptionalHeader.SizeOfHeaders);
    sections = IMAGE_FIRST_SECTION(pe);
    if ((BYTE *)(sections + pe->FileHeader.NumberOfSections) > disk + length) goto invalid;
    for (unsigned i = 0; i < pe->FileHeader.NumberOfSections; ++i) {
        if ((uint64_t)sections[i].PointerToRawData + sections[i].SizeOfRawData > (size_t)length ||
            (uint64_t)sections[i].VirtualAddress + sections[i].SizeOfRawData >
                ((*image_size + 0xfff) & ~(size_t)0xfff)) goto invalid;
        memcpy(image + sections[i].VirtualAddress, disk + sections[i].PointerToRawData, sections[i].SizeOfRawData);
    }
    if (*image_size < FH_MATCH_RVA + FH_MATCH_SIZE ||
        memcmp(image + FH_MATCH_GETTER_RVA, match_getter, sizeof(match_getter))) goto invalid;
    put32(image + FH_MATCH_GETTER_RVA + 1, (uint32_t)(uintptr_t)(image + FH_MATCH_RVA));
    if (!memcmp(image + 0x87eb0, tournament_getter, sizeof(tournament_getter))) {
        put32(image + 0x87eb1, (uint32_t)(uintptr_t)(image + 0x530ee0));
        *oracle_available = TRUE;
    }
    for (unsigned i = 0; i < pe->FileHeader.NumberOfSections; ++i) {
        DWORD old;
        size_t n = sections[i].Misc.VirtualSize;
        if (n < sections[i].SizeOfRawData) n = sections[i].SizeOfRawData;
        if ((sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && n &&
            !VirtualProtect(image + sections[i].VirtualAddress, n, PAGE_EXECUTE_READ, &old)) goto invalid;
    }
    FlushInstructionCache(GetCurrentProcess(), image, *image_size);
    goto done;
invalid:
    VirtualFree(image, 0, MEM_RELEASE);
    image = NULL;
done:
    free(disk);
    fclose(file);
    return image;
}

static void change(BYTE *image, uint32_t rva, BYTE value) {
    DWORD old, ignored;
    check(VirtualProtect(image + rva, 1, PAGE_EXECUTE_READWRITE, &old), "test page writable");
    image[rva] = value;
    FlushInstructionCache(GetCurrentProcess(), image + rva, 1);
    check(VirtualProtect(image + rva, 1, old, &ignored), "test page restored");
}

static int native_eligible(unsigned tournament) {
    return tournament == 14 || tournament == 15 || tournament == 16 || tournament == 19 || tournament == 20;
}

static void native_matrix(BYTE *image) {
    const int limits[] = {-32768, -2, -1, 0, 1, 5, 10, 20, 40, 45, 50, 32767};
    const BYTE pendings[] = {0, 1, 255}, initials[] = {0, 1, 127};
    const unsigned tournaments[] = {0, 1, 14, 15, 16, 19, 20, 39};
    BYTE manager[0x120], *match = image + FH_MATCH_RVA;
    Activation activate = (Activation)(image + FH_ACTIVATION_RVA);
    for (size_t t = 0; t < sizeof(tournaments)/sizeof(tournaments[0]); ++t) {
        put32(image + 0x530ee0, tournaments[t]);
        for (size_t l = 0; l < sizeof(limits)/sizeof(limits[0]); ++l)
        for (size_t p = 0; p < sizeof(pendings)/sizeof(pendings[0]); ++p)
        for (unsigned flags = 0; flags < 256; ++flags)
        for (size_t initial = 0; initial < sizeof(initials)/sizeof(initials[0]); ++initial) {
            int expected = limits[l] > 0 && pendings[p] != 0 && !(flags & 3);
            memset(manager, 0xa5, sizeof(manager));
            manager[FH_ACTIVE_OFFSET] = initials[initial];
            put16(match + FH_OVER_LIMIT_OFFSET, limits[l]);
            match[FH_PENDING_OFFSET] = pendings[p];
            match[FH_FLAGS_OFFSET] = (BYTE)flags;
            activate(manager);
            check(manager[FH_ACTIVE_OFFSET] == expected, "patched native activation decision");
            check(match[FH_PENDING_OFFSET] == (expected ? 0 : pendings[p]), "native pending-state consumption");
            check(match[FH_FLAGS_OFFSET] == flags, "delivery flags untouched");
            check(manager[FH_ACTIVE_OFFSET - 1] == 0xa5 && manager[FH_ACTIVE_OFFSET + 1] == 0xa5,
                  "adjacent manager bytes untouched");
            check(*(uint32_t *)(image + 0x530ee0) == tournaments[t], "tournament identity untouched");
            ++cases;
        }
    }
}

static void mutation_tests(BYTE *image, size_t size) {
    BYTE *snapshot = malloc(size), *match = image + FH_MATCH_RVA;
    FH_Image inspected;
    IMAGE_SECTION_HEADER *sections;
    check(snapshot != NULL, "snapshot allocation");
    if (!snapshot) return;
    check(FH_InspectImage(image, &inspected, capture), "inspect mapped actual executable");
    check(FH_Validate(&inspected, capture), "actual executable signatures accepted after relocation");
    for (size_t s = 0; s < sizeof(fh_signatures)/sizeof(fh_signatures[0]); ++s) {
        /* Every byte is a requirement, not just the first opcode. */
        for (size_t b = 0; b < fh_signatures[s].size; ++b) {
            uint32_t rva = fh_signatures[s].rva + (uint32_t)b;
            BYTE original = image[rva];
            change(image, rva, (BYTE)(original ^ 1));
            memcpy(snapshot, image, size);
            check(!FH_Install(image, capture), "required-byte mutation rejected");
            check(!memcmp(snapshot, image, size), "rejected image remains byte-for-byte unchanged");
            change(image, rva, original);
        }
    }
    for (unsigned i = 0; i < 6; ++i) {
        BYTE old = image[FH_MATCH_GETTER_RVA + i];
        change(image, FH_MATCH_GETTER_RVA + i, (BYTE)(old ^ 1));
        check(!FH_Install(image, capture), "getter mutation rejected");
        check(!memcmp(image + FH_ACTIVATION_RVA, fh_activation, sizeof(fh_activation)), "getter rejection leaves activation unchanged");
        change(image, FH_MATCH_GETTER_RVA + i, old);
    }
    sections = IMAGE_FIRST_SECTION(inspected.pe);
    for (unsigned i = 0; i < inspected.pe->FileHeader.NumberOfSections; ++i) {
        if (FH_ACTIVATION_RVA >= sections[i].VirtualAddress &&
            FH_ACTIVATION_RVA < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
            DWORD old = sections[i].Characteristics;
            sections[i].Characteristics &= ~IMAGE_SCN_MEM_EXECUTE;
            check(!FH_Install(image, capture), "non-executable code section rejected");
            sections[i].Characteristics = old;
        }
    }
    {
        DWORD old_size = inspected.pe->OptionalHeader.SizeOfImage;
        WORD old_machine = inspected.pe->FileHeader.Machine;
        inspected.pe->OptionalHeader.SizeOfImage = FH_ACTIVATION_RVA + 4;
        check(!FH_Install(image, capture), "truncated declared image rejected");
        inspected.pe->OptionalHeader.SizeOfImage = old_size;
        inspected.pe->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        check(!FH_Install(image, capture), "wrong architecture rejected");
        inspected.pe->FileHeader.Machine = old_machine;
        inspected.pe->OptionalHeader.SizeOfImage = old_size + 0x10000;
        check(FH_InspectImage(image, &inspected, capture) && FH_Validate(&inspected, capture),
              "larger modified image accepted when required ranges are present");
        inspected.pe->OptionalHeader.SizeOfImage = old_size;
    }
    {
        DWORD old, ignored;
        check(VirtualProtect(image + FH_ACTIVATION_RVA, 1, PAGE_READONLY, &old), "remove actual execute permission");
        memcpy(snapshot, image, size);
        check(!FH_Install(image, capture), "non-executable mapped code page rejected");
        check(!memcmp(snapshot, image, size), "mapped protection rejection leaves all bytes unchanged");
        check(VirtualProtect(image + FH_ACTIVATION_RVA, 1, old, &ignored), "restore actual execute permission");
        check(VirtualProtect(match + 0x21000, 0x1000, PAGE_NOACCESS, &old), "guard fixture match page");
        check(!FH_Install(image, capture), "inaccessible required match storage rejected safely");
        check(VirtualProtect(match + 0x21000, 0x1000, old, &ignored), "unguard fixture match page");
    }
    check(!FH_Install(NULL, capture), "null image rejected safely");
    free(snapshot);
}

int main(int argc, char **argv) {
    BYTE *image, *snapshot, manager[0x120] = {0};
    size_t size;
    FH_Image inspected;
    DWORD old_protection;
    MEMORY_BASIC_INFORMATION before, after;
    BOOL oracle_available;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 3) { fprintf(stderr, "Usage: native_test ASI GAME_EXE\n"); return 2; }
    image = load_image(argv[2], &size, &oracle_available);
    check(image != NULL, "map actual game executable in private memory");
    if (!image) return 1;
    if (!FH_InspectImage(image, &inspected, capture) || !FH_Validate(&inspected, capture)) {
        fprintf(stderr, "Fixture rejected before any native execution: %s\n", last_log);
        VirtualFree(image, 0, MEM_RELEASE);
        return 1;
    }
    /* Establish that the unmodified native routine has the documented whitelist. */
    if (oracle_available) {
        for (unsigned t = 0; t <= 40; ++t) {
            put32(image + 0x530ee0, t);
            image[FH_MATCH_RVA + FH_PENDING_OFFSET] = 1;
            image[FH_MATCH_RVA + FH_FLAGS_OFFSET] = 0;
            ((Activation)(image + FH_ACTIVATION_RVA))(manager);
            check(manager[FH_ACTIVE_OFFSET] == native_eligible(t), "original executable whitelist oracle");
        }
        puts("Native whitelist oracle passed. Checking required routines and malformed images...");
    } else {
        puts("Original tournament getter differs: skipping optional whitelist oracle; required routines validated before patched native execution.");
    }
    mutation_tests(image, size);
    /* Accept a genuine unrelated code mutation instead of enforcing a hash. */
    change(image, 0x1000, (BYTE)(image[0x1000] ^ 1));
    snapshot = malloc(size);
    check(snapshot != NULL, "installation snapshot allocation");
    if (!snapshot) return 1;
    memcpy(snapshot, image, size);
    VirtualQuery(image + FH_PATCH_RVA, &before, sizeof(before));
    old_protection = before.Protect;
    check(FH_Install(image, capture), "modified but signature-compatible executable accepted");
    VirtualQuery(image + FH_PATCH_RVA, &after, sizeof(after));
    check(after.Protect == old_protection, "native code page protection restored");
    check(!memcmp(snapshot, image, FH_PATCH_RVA), "all bytes before patch unchanged");
    check(!memcmp(snapshot + FH_PATCH_RVA + FH_PATCH_SIZE, image + FH_PATCH_RVA + FH_PATCH_SIZE,
                  size - FH_PATCH_RVA - FH_PATCH_SIZE), "all bytes after patch unchanged");
    check(image[FH_PATCH_RVA] == 0xe8, "native-only patch installed");
    check(FH_InspectImage(image, &inspected, capture), "patched image still valid PE");
    puts("Executing patched x86 routine across formats, tournaments, pending states and all delivery flags...");
    native_matrix(image);
    memcpy(snapshot, image, size);
    check(!FH_Install(image, capture), "duplicate or overlapping patch rejected");
    check(!memcmp(snapshot, image, size), "duplicate rejection does not alter image");
    free(snapshot);
    VirtualFree(image, 0, MEM_RELEASE);
    {
        HMODULE module = LoadLibraryA(argv[1]);
        void (__cdecl *initialize)(void);
        LONG (__cdecl *get_status)(void);
        check(module != NULL, "Windows loads compiled 32-bit ASI");
        if (module) {
            initialize = (void (__cdecl *)(void))GetProcAddress(module, "InitializeASI");
            get_status = (LONG (__cdecl *)(void))GetProcAddress(module, "GetFreeHitStatus");
            check(initialize && get_status, "undecorated Ultimate ASI Loader exports");
            if (initialize && get_status) {
                check(get_status() == 0, "DllMain performs no initialization/patching");
                initialize();
                check(get_status() == -1, "ASI safely rejects the non-game test host");
                initialize();
                check(get_status() == -1, "InitializeASI is idempotent");
            }
            FreeLibrary(module);
        }
    }
    printf("%u native activation cases, %u checks, %u warning-path observations, %d failures.\n",
           cases, checks, warnings, failures);
    return failures ? 1 : 0;
}
