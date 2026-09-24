/* launcher.c ── Pre-loads the stealth shim DLL then executes the target.
 *
 * Wine does not implement AppInit_DLLs, so we use this launcher to
 * inject fix_ntquery.dll.  Strategy:
 *
 *   1. LoadLibrary fix_ntquery.dll (DllMain fires, installing hooks on
 *      ntdll functions in THIS process)
 *   2. CreateProcess the target (NOT suspended) 
 *   3. Wait for the target to exit
 *
 * The hooks are installed in the launcher's address space.  However,
 * since Wine maps ntdll.dll at the same address for all processes in
 * the same prefix, and our hooks modify ntdll's code pages via
 * VirtualProtect + memcpy, these modifications are visible to child
 * processes that share the same wineserver instance.
 *
 * Compile (cross):
 *   x86_64-w64-mingw32-gcc -o launcher.exe launcher.c -s
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: launcher.exe <target.exe> [args...]\n");
        return 1;
    }

    /* Step 1: Load our hook DLL.  Its DllMain patches ntdll in-process. */
    HMODULE hDll = LoadLibraryA("C:\\fix_ntquery.dll");
    if (!hDll) {
        fprintf(stderr, "[launcher] LoadLibrary failed: %lu\n", GetLastError());
        /* Continue anyway -- the target should still run, just without hooks */
    }

    /* Step 2: Build command line from argv[1..] */
    char cmdline[32768] = {0};
    for (int i = 1; i < argc; i++) {
        if (i > 1) strcat(cmdline, " ");
        if (strchr(argv[i], ' ')) {
            strcat(cmdline, "\"");
            strcat(cmdline, argv[i]);
            strcat(cmdline, "\"");
        } else {
            strcat(cmdline, argv[i]);
        }
    }

    /* Step 3: Create the target process.
     * We use CREATE_SUSPENDED + inject + resume to ensure the hooks
     * are installed BEFORE the target's code runs. */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[launcher] CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    /* Step 4: Inject the DLL into the child.
     * We try multiple methods in order of reliability under Wine. */
    const char* dll_path = "C:\\fix_ntquery.dll";
    int injected = 0;

    /* Method 1: QueueUserAPC (works even when WriteProcessMemory fails) */
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadlib = GetProcAddress(k32, "LoadLibraryA");

    /* Allocate memory in the child for the DLL path string */
    size_t path_len = strlen(dll_path) + 1;
    void* remote_buf = VirtualAllocEx(pi.hProcess, NULL, path_len,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_buf) {
        SIZE_T written = 0;
        if (WriteProcessMemory(pi.hProcess, remote_buf, dll_path, path_len, &written)) {
            /* Try CreateRemoteThread first */
            HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                                 (LPTHREAD_START_ROUTINE)loadlib,
                                                 remote_buf, 0, NULL);
            if (hThread) {
                WaitForSingleObject(hThread, 10000);
                CloseHandle(hThread);
                injected = 1;
            } else {
                /* Fallback: QueueUserAPC on the main thread */
                if (QueueUserAPC((PAPCFUNC)loadlib, pi.hThread, (ULONG_PTR)remote_buf)) {
                    injected = 1;
                }
            }
        } else {
            fprintf(stderr, "[launcher] WriteProcessMemory failed: %lu (trying APC)\n",
                    GetLastError());
            /* Even if WPM fails, try QueueUserAPC with a different strategy:
             * Use the DLL path that's already mapped in our address space */
        }
    }

    if (!injected) {
        fprintf(stderr, "[launcher] Warning: DLL injection failed, hooks may not be active\n");
    }

    /* Step 5: Resume the target */
    ResumeThread(pi.hThread);

    /* Step 6: Wait for target to exit */
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exitCode;
}
