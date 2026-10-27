#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "patch.h"

static HMODULE module_self;
static volatile LONG initialized, status;
static const char reference_sha[] = "d776dba0cc506b968f7d228e036cf42aeb4abe45a8d1ad0d7226cdebf91553a2";

static void log_line(const char *line) {
    WCHAR path[32768];
    SYSTEMTIME time;
    char prefix[48];
    HANDLE file;
    DWORD n, written;
    n = GetModuleFileNameW(module_self, path, sizeof(path) / sizeof(path[0]));
    if (!n || n >= sizeof(path) / sizeof(path[0])) return;
    while (n && path[n - 1] != L'\\' && path[n - 1] != L'/') --n;
    if (n + sizeof(L"Cricket07FreeHit.log") / sizeof(WCHAR) > sizeof(path) / sizeof(path[0])) return;
    memcpy(path + n, L"Cricket07FreeHit.log", sizeof(L"Cricket07FreeHit.log"));
    file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return;
    GetLocalTime(&time);
    snprintf(prefix, sizeof(prefix), "[%04u-%02u-%02u %02u:%02u:%02u] ",
             time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
    WriteFile(file, prefix, (DWORD)strlen(prefix), &written, NULL);
    WriteFile(file, line, (DWORD)strlen(line), &written, NULL);
    WriteFile(file, "\r\n", 2, &written, NULL);
    CloseHandle(file);
}

/* Diagnostic only: acceptance depends on mapped PE and routine signatures. */
static void log_hash(void) {
    WCHAR path[32768];
    BYTE buffer[16384], digest[32];
    char actual[65], line[260];
    HANDLE file = INVALID_HANDLE_VALUE;
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    DWORD n, size = sizeof(digest);
    BOOL ok = FALSE;
    n = GetModuleFileNameW(NULL, path, sizeof(path) / sizeof(path[0]));
    if (!n || n >= sizeof(path) / sizeof(path[0])) goto done;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE ||
        !CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto done;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &n, NULL)) goto done;
        if (!n) break;
        if (!CryptHashData(hash, buffer, n, 0)) goto done;
    }
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0) || size != sizeof(digest)) goto done;
    for (unsigned i = 0; i < sizeof(digest); ++i) snprintf(actual + 2 * i, 3, "%02x", digest[i]);
    snprintf(line, sizeof(line), strcmp(actual, reference_sha) ?
             "WARNING: executable SHA-256 differs from reference (%s). Modified executable detected; continuing ONLY if required PE/layout and routine checks pass." :
             "Executable SHA-256 matches reference: %s.", actual);
    log_line(line);
    ok = TRUE;
done:
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (!ok) log_line("WARNING: executable SHA-256 unavailable; continuing ONLY if required PE/layout and routine checks pass.");
}

void InitializeASI(void) {
    if (InterlockedCompareExchange(&initialized, 1, 0)) return;
    log_line("Cricket07FreeHit 1.0 initializing (32-bit Ultimate ASI Loader; SHA-256 diagnostic only).");
    log_hash();
    if (!FH_Install((BYTE *)GetModuleHandleW(NULL), log_line)) {
        InterlockedExchange(&status, -1);
        return;
    }
    InterlockedExchange(&status, 1);
}

LONG GetFreeHitStatus(void) { return InterlockedCompareExchange(&status, 0, 0); }

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        module_self = module;
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}
