// inject.exe — loads dumper.dll into a running process (by PID or image name).
// Usage: inject.exe <pid | NinjaTrader.exe> <full\path\to\dumper.dll>
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

static DWORD FindPidByName(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: inject.exe <pid|exe-name> <full path to dumper.dll>\n");
        return 2;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    if (pid == 0) pid = FindPidByName(argv[1]);
    if (pid == 0) { fprintf(stderr, "process not found: %s\n", argv[1]); return 1; }

    char dllPath[MAX_PATH];
    if (!GetFullPathNameA(argv[2], MAX_PATH, dllPath, nullptr)) {
        fprintf(stderr, "bad dll path\n"); return 1;
    }

    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                              PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                              FALSE, pid);
    if (!proc) { fprintf(stderr, "OpenProcess failed: %lu\n", GetLastError()); return 1; }

    SIZE_T len = strlen(dllPath) + 1;
    void* remote = VirtualAllocEx(proc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { fprintf(stderr, "VirtualAllocEx failed\n"); CloseHandle(proc); return 1; }

    if (!WriteProcessMemory(proc, remote, dllPath, len, nullptr)) {
        fprintf(stderr, "WriteProcessMemory failed\n"); CloseHandle(proc); return 1;
    }

    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE th = CreateRemoteThread(proc, nullptr, 0, loadLib, remote, 0, nullptr);
    if (!th) { fprintf(stderr, "CreateRemoteThread failed: %lu\n", GetLastError()); CloseHandle(proc); return 1; }

    WaitForSingleObject(th, INFINITE);
    printf("injected %s into pid %lu\n", dllPath, pid);
    CloseHandle(th);
    CloseHandle(proc);
    return 0;
}
