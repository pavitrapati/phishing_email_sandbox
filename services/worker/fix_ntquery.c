/* fix_ntquery.c ── Stealth shim for Wine sandbox (powrprof.dll proxy)
 *
 * Loaded via DLL search-order hijacking: our DLL sits in
 * C:\windows\system32\powrprof.dll and proxies to the real Wine DLL
 * that was renamed to powrprof_real.dll.
 *
 * Wine 8.0 already handles NtQueryObject and NtSetInformationThread
 * correctly (returns STATUS_SUCCESS), so we no longer inline-hook
 * ntdll functions.  The remaining purpose of this DLL is:
 *
 *   1. Proxy GetPwrCapabilities (and any other powrprof exports the
 *      target might call) to the real Wine implementation.
 *
 * Compile (cross):
 *   x86_64-w64-mingw32-gcc -shared -o powrprof.dll fix_ntquery.c -s
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>

/* ── Proxy: GetPwrCapabilities ────────────────────────────────────── */
static FARPROC pGetPwrCapabilities = NULL;
static HMODULE hRealPowrprof = NULL;

static void load_real_powrprof(void)
{
    if (hRealPowrprof) return;
    /* Our DLL replaced the original system32\powrprof.dll.
       The real Wine one was renamed to powrprof_real.dll by the entrypoint. */
    hRealPowrprof = LoadLibraryA("C:\\windows\\system32\\powrprof_real.dll");
    if (hRealPowrprof) {
        pGetPwrCapabilities = GetProcAddress(hRealPowrprof, "GetPwrCapabilities");
    }
}

__declspec(dllexport) BOOLEAN WINAPI GetPwrCapabilities(PVOID SystemPowerCapabilities)
{
    load_real_powrprof();
    if (pGetPwrCapabilities) {
        return ((BOOLEAN (WINAPI *)(PVOID))pGetPwrCapabilities)(SystemPowerCapabilities);
    }
    return 0;
}

/* ── DllMain ──────────────────────────────────────────────────────── */
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_DETACH && hRealPowrprof) {
        FreeLibrary(hRealPowrprof);
    }
    return TRUE;
}
