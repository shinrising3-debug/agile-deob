// IlDumper — captures decrypted IL at JIT time.
//
// Agile.NET's native runtime decrypts each method's IL and hands it to the JIT
// via ICorJitCompiler::compileMethod. We hook the same vtable slot; by the time
// our hook runs, info->ILCode points at the *decrypted* IL.
//
// SAFE BY DEFAULT: with no ILDUMP_TOKIDX set, the hook only READS the IL and
// writes a diagnostic log (dump.log) — it makes no low-level vtable calls, so it
// cannot crash the host. That first run proves capture works. Once we know the
// token/EH vtable indices for your CLR, set ILDUMP_TOKIDX (and ILDUMP_EHIDX) and
// it writes a full .ildump for `agile-deob reinject`.
//
// Portable across MinGW-w64 and MSVC. Windows x64 / .NET Framework 4.x.
#include "corjit_min.h"
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cstdint>

static CompileMethod_t g_orig = nullptr;
static CRITICAL_SECTION g_cs;
static std::vector<unsigned char> g_buf;     // serialized ILDUMP02 records
static unsigned g_count = 0;                  // records with a resolved MethodDef token
static unsigned g_seen = 0;                   // all methods seen
static char g_out[MAX_PATH]  = {0};
static char g_log[MAX_PATH]  = {0};
static int  g_tokIdx = -1;                    // ILDUMP_TOKIDX (vtable slot), -1 = probe only
static int  g_ehIdx  = -1;                    // ILDUMP_EHIDX

static void logf(const char* fmt, ...) {
    FILE* f = fopen(g_log, "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f); fclose(f);
}

static void put32(std::vector<unsigned char>& b, unsigned v) {
    for (int i = 0; i < 4; i++) b.push_back((unsigned char)(v >> (8*i)));
}
static void put16(std::vector<unsigned char>& b, unsigned short v) {
    b.push_back((unsigned char)(v & 0xFF)); b.push_back((unsigned char)(v >> 8));
}
static void put64(std::vector<unsigned char>& b, unsigned long long v) {
    for (int i = 0; i < 8; i++) b.push_back((unsigned char)(v >> (8*i)));
}

static void WriteAll() {
    FILE* f = fopen(g_out, "wb");
    if (!f) return;
    fwrite("ILDUMP02", 1, 8, f);
    unsigned c = g_count;
    unsigned char hdr[4] = { (unsigned char)c, (unsigned char)(c>>8),
                             (unsigned char)(c>>16), (unsigned char)(c>>24) };
    fwrite(hdr, 1, 4, f);
    if (!g_buf.empty()) fwrite(g_buf.data(), 1, g_buf.size(), f);
    fclose(f);
}

static int Hooked(void* thisptr, void* comp, CORINFO_METHOD_INFO* info,
                  unsigned flags, BYTE** ne, ULONG* ns) {
    int rc = g_orig(thisptr, comp, info, flags, ne, ns);  // decrypt + real JIT first
    if (!info || !info->ILCode || info->ILCodeSize == 0 || !comp) return rc;

    EnterCriticalSection(&g_cs);
    g_seen++;

    mdToken token = 0;
    if (g_tokIdx >= 0) {
        void** vt = *(void***)comp;
        GetMethodDefFromMethod_t getTok = (GetMethodDefFromMethod_t)vt[g_tokIdx];
        token = getTok(comp, info->ftn);        // only when an index is configured
    }

    // Diagnostic log for the first methods seen.
    if (g_seen <= 20) {
        char hx[49]; int k = 0;
        for (unsigned i = 0; i < info->ILCodeSize && i < 16; i++)
            k += sprintf(hx + k, "%02x", info->ILCode[i]);
        logf("  method#%u scope=%p ilSize=%u maxStack=%u token=0x%08x il=%s",
             g_seen, info->scope, info->ILCodeSize, info->maxStack, token, hx);
    }

    if (g_tokIdx >= 0 && (token >> 24) == 0x06) {
        put32(g_buf, token);
        put64(g_buf, (unsigned long long)(uintptr_t)info->scope);
        put16(g_buf, (unsigned short)info->maxStack);
        put16(g_buf, (unsigned short)((info->options & 0x10) ? 1 : 0));
        put32(g_buf, info->ILCodeSize);
        put32(g_buf, info->locals.cbSig);
        put32(g_buf, info->EHcount);
        g_buf.insert(g_buf.end(), info->ILCode, info->ILCode + info->ILCodeSize);
        if (info->locals.pSig && info->locals.cbSig)
            g_buf.insert(g_buf.end(), info->locals.pSig, info->locals.pSig + info->locals.cbSig);
        if (g_ehIdx >= 0 && info->EHcount > 0) {
            void** vt = *(void***)comp;
            GetEHinfo_t getEH = (GetEHinfo_t)vt[g_ehIdx];
            for (unsigned i = 0; i < info->EHcount; i++) {
                CORINFO_EH_CLAUSE c; memset(&c, 0, sizeof(c));
                getEH(comp, info->ftn, i, &c);
                put32(g_buf, c.Flags); put32(g_buf, c.TryOffset); put32(g_buf, c.TryLength);
                put32(g_buf, c.HandlerOffset); put32(g_buf, c.HandlerLength);
                put32(g_buf, c.ClassTokenOrFilterOffset);
            }
        }
        g_count++;
        if ((g_count % 50) == 0) WriteAll();
    }
    LeaveCriticalSection(&g_cs);
    return rc;
}

static DWORD WINAPI Install(LPVOID) {
    HMODULE jit = nullptr;
    for (int i = 0; i < 1200 && !jit; i++) { jit = GetModuleHandleA("clrjit.dll"); if (!jit) Sleep(100); }
    if (!jit) { logf("clrjit.dll not found"); return 0; }
    GetJit_t getJit = (GetJit_t)GetProcAddress(jit, "getJit");
    if (!getJit) { logf("getJit not found"); return 0; }
    void* jc = getJit();
    if (!jc) { logf("getJit() returned null"); return 0; }
    void** vt = *(void***)jc;
    g_orig = (CompileMethod_t)vt[0];
    DWORD old;
    if (VirtualProtect(&vt[0], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) {
        vt[0] = (void*)&Hooked;
        VirtualProtect(&vt[0], sizeof(void*), old, &old);
        logf("JIT hook installed (tokIdx=%d ehIdx=%d). Exercise the indicator now.", g_tokIdx, g_ehIdx);
    } else {
        logf("VirtualProtect failed");
    }
    return 0;
}

static int EnvInt(const char* name, int dflt) {
    char v[32];
    DWORD n = GetEnvironmentVariableA(name, v, sizeof(v));
    if (n == 0 || n >= sizeof(v)) return dflt;
    return atoi(v);
}

// Read "TOKIDX=NNN" / "EHIDX=MMM" from an index file (default C:\agiledump.idx).
// A file is used instead of env vars so it also works when the DLL is injected
// into an already-running NinjaTrader (which didn't inherit our environment).
static void ReadIdxFile() {
    char path[MAX_PATH];
    if (GetEnvironmentVariableA("ILDUMP_IDX", path, MAX_PATH) == 0)
        strcpy(path, "C:\\agiledump.idx");
    FILE* f = fopen(path, "r");
    if (!f) return;
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        int v;
        if (sscanf(line, "TOKIDX=%d", &v) == 1) g_tokIdx = v;
        else if (sscanf(line, "EHIDX=%d", &v) == 1) g_ehIdx = v;
    }
    fclose(f);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        InitializeCriticalSection(&g_cs);
        if (GetEnvironmentVariableA("ILDUMP_OUT", g_out, MAX_PATH) == 0) strcpy(g_out, "C:\\agiledump.ildump");
        if (GetEnvironmentVariableA("ILDUMP_LOG", g_log, MAX_PATH) == 0) strcpy(g_log, "C:\\agiledump.log");
        g_tokIdx = EnvInt("ILDUMP_TOKIDX", -1);
        g_ehIdx  = EnvInt("ILDUMP_EHIDX", -1);
        ReadIdxFile();   // a C:\agiledump.idx file overrides, for injected runs
        FILE* f = fopen(g_log, "w"); if (f) { fprintf(f, "IlDumper loaded. mode=%s\n",
            g_tokIdx >= 0 ? "FULL (writing .ildump)" : "PROBE (log only, safe)"); fclose(f); }
        CreateThread(nullptr, 0, Install, nullptr, 0, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
        EnterCriticalSection(&g_cs);
        if (g_tokIdx >= 0) WriteAll();
        logf("detach: methods seen=%u, records written=%u", g_seen, g_count);
        LeaveCriticalSection(&g_cs);
    }
    return TRUE;
}
