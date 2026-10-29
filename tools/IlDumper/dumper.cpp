// IlDumper — captures decrypted IL at JIT time and writes an .ildump that
// `agile-deob reinject` folds back into the assembly.
//
// Technique: Agile.NET's native runtime decrypts each method's IL and feeds it
// to the JIT by hooking ICorJitCompiler::compileMethod. We install our own hook
// on the same vtable slot; by the time compileMethod runs, info->ILCode points
// at the *decrypted* IL. We record it, keyed by (module scope, MethodDef token).
//
// ⚠ Reference implementation. Windows x64 / .NET Framework 4.x only. Untested
// as shipped — the two vtable indices in corjit_min.h MUST be set for your exact
// runtime (README → "Tuning"), or tokens/EH come out empty and reinject finds
// no matches.
#include "corjit_min.h"
#include <vector>
#include <mutex>
#include <cstdio>
#include <cstring>

static CompileMethod_t  g_origCompile = nullptr;
static std::mutex       g_lock;
static std::vector<unsigned char> g_buf;   // serialized records
static unsigned         g_count = 0;
static char             g_outPath[MAX_PATH] = {0};

static void put32(std::vector<unsigned char>& b, unsigned v) {
    b.push_back(v & 0xFF); b.push_back((v >> 8) & 0xFF);
    b.push_back((v >> 16) & 0xFF); b.push_back((v >> 24) & 0xFF);
}
static void put16(std::vector<unsigned char>& b, unsigned short v) {
    b.push_back(v & 0xFF); b.push_back((v >> 8) & 0xFF);
}
static void put64(std::vector<unsigned char>& b, unsigned long long v) {
    for (int i = 0; i < 8; i++) b.push_back((unsigned char)((v >> (8 * i)) & 0xFF));
}

static void WriteAll() {
    FILE* f = nullptr;
    if (fopen_s(&f, g_outPath, "wb") != 0 || !f) return;
    fwrite("ILDUMP02", 1, 8, f);
    unsigned char hdr[4] = {
        (unsigned char)(g_count & 0xFF), (unsigned char)((g_count >> 8) & 0xFF),
        (unsigned char)((g_count >> 16) & 0xFF), (unsigned char)((g_count >> 24) & 0xFF) };
    fwrite(hdr, 1, 4, f);
    if (!g_buf.empty()) fwrite(g_buf.data(), 1, g_buf.size(), f);
    fclose(f);
}

static int HookedCompileMethod(void* thisptr, void* comp, CORINFO_METHOD_INFO* info,
                               unsigned flags, BYTE** nativeEntry, ULONG* nativeSizeOfCode) {
    // Let the decryption (downstream protector hook) and the real JIT run first.
    int rc = g_origCompile(thisptr, comp, info, flags, nativeEntry, nativeSizeOfCode);

    if (info && info->ILCode && info->ILCodeSize > 0 && comp) {
        void** vtbl = *(void***)comp;

        mdToken token = 0;
        if (IDX_getMethodDefFromMethod != 0) {
            auto getTok = (GetMethodDefFromMethod_t)vtbl[IDX_getMethodDefFromMethod];
            token = getTok(comp, info->ftn);
        }

        // Only MethodDef tokens (0x06......). Skip anything we couldn't resolve.
        if ((token >> 24) == 0x06) {
            std::lock_guard<std::mutex> g(g_lock);

            put32(g_buf, token);
            put64(g_buf, (unsigned long long)info->scope);
            put16(g_buf, (unsigned short)info->maxStack);
            put16(g_buf, (unsigned short)((info->options & 0x10) ? 1 : 0)); // CORINFO_OPT_INIT_LOCALS
            put32(g_buf, info->ILCodeSize);
            put32(g_buf, info->locals.cbSig);
            put32(g_buf, info->EHcount);

            g_buf.insert(g_buf.end(), info->ILCode, info->ILCode + info->ILCodeSize);
            if (info->locals.pSig && info->locals.cbSig)
                g_buf.insert(g_buf.end(), info->locals.pSig, info->locals.pSig + info->locals.cbSig);

            if (IDX_getEHinfo != 0 && info->EHcount > 0) {
                auto getEH = (GetEHinfo_t)vtbl[IDX_getEHinfo];
                for (unsigned i = 0; i < info->EHcount; i++) {
                    CORINFO_EH_CLAUSE c = {0};
                    getEH(comp, info->ftn, i, &c);
                    put32(g_buf, c.Flags);
                    put32(g_buf, c.TryOffset);
                    put32(g_buf, c.TryLength);
                    put32(g_buf, c.HandlerOffset);
                    put32(g_buf, c.HandlerLength);
                    put32(g_buf, c.ClassTokenOrFilterOffset);
                }
            }

            g_count++;
            if ((g_count % 50) == 0) WriteAll();   // periodic flush
        }
    }
    return rc;
}

static DWORD WINAPI InstallHook(LPVOID) {
    HMODULE jit = nullptr;
    for (int i = 0; i < 600 && !jit; i++) {   // wait up to ~60s for the JIT
        jit = GetModuleHandleA("clrjit.dll");
        if (!jit) Sleep(100);
    }
    if (!jit) return 0;

    auto getJit = (GetJit_t)GetProcAddress(jit, "getJit");
    if (!getJit) return 0;
    void* jitComp = getJit();
    if (!jitComp) return 0;

    void** vtbl = *(void***)jitComp;         // ICorJitCompiler vtable; slot 0 = compileMethod
    g_origCompile = (CompileMethod_t)vtbl[0];

    DWORD old;
    if (VirtualProtect(&vtbl[0], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) {
        vtbl[0] = (void*)&HookedCompileMethod;
        VirtualProtect(&vtbl[0], sizeof(void*), old, &old);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        // Output path from ILDUMP_OUT, else alongside this DLL as out.ildump.
        DWORD n = GetEnvironmentVariableA("ILDUMP_OUT", g_outPath, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) strcpy_s(g_outPath, "C:\\agiledump.ildump");
        CreateThread(nullptr, 0, InstallHook, nullptr, 0, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
        std::lock_guard<std::mutex> g(g_lock);
        WriteAll();   // final flush
    }
    return TRUE;
}
