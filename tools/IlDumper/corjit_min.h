// Minimal subset of the CLR's JIT interface (corinfo.h / corjit.h) needed to
// capture decrypted IL at JIT time on 64-bit .NET Framework 4.x (the runtime
// NinjaTrader 8 uses).
//
// ⚠ VERSION-SENSITIVE. These layouts come from the public corinfo.h and are
// stable across .NET Framework 4.6–4.8 x64, but NOT guaranteed. If dumps come
// out garbage, the struct layout or a vtable index below is off for your exact
// clr.dll/clrjit.dll build — see README → "Tuning".
#pragma once
#include <windows.h>

typedef void*          CORINFO_METHOD_HANDLE;
typedef void*          CORINFO_MODULE_HANDLE;
typedef void*          CORINFO_CLASS_HANDLE;
typedef void*          CORINFO_ARG_LIST_HANDLE;
typedef const BYTE*    PCCOR_SIGNATURE;
typedef unsigned       mdToken;

enum CorJitResult { CORJIT_OK = 0 };

struct CORINFO_SIG_INST {
    unsigned              classInstCount;
    CORINFO_CLASS_HANDLE* classInst;
    unsigned              methInstCount;
    CORINFO_CLASS_HANDLE* methInst;
};

// Note: the bitfields (retType:8, flags:8, numArgs:16) pack into one 32-bit word.
struct CORINFO_SIG_INFO {
    int                     callConv;
    CORINFO_CLASS_HANDLE    retTypeClass;
    CORINFO_CLASS_HANDLE    retTypeSigClass;
    BYTE                    retType;
    BYTE                    flags;
    unsigned short          numArgs;
    CORINFO_SIG_INST        sigInst;
    CORINFO_ARG_LIST_HANDLE args;
    PCCOR_SIGNATURE         pSig;     // <- raw signature blob
    unsigned                cbSig;    // <- its length
    CORINFO_MODULE_HANDLE   scope;
    mdToken                 token;
};

struct CORINFO_METHOD_INFO {
    CORINFO_METHOD_HANDLE ftn;
    CORINFO_MODULE_HANDLE scope;
    BYTE*                 ILCode;     // <- decrypted IL by the time compileMethod runs
    unsigned              ILCodeSize;
    unsigned              maxStack;
    unsigned              EHcount;
    int                   options;
    int                   regionKind;
    CORINFO_SIG_INFO      args;
    CORINFO_SIG_INFO      locals;     // locals.pSig/cbSig = local var signature blob
};

enum CORINFO_EH_CLAUSE_FLAGS {
    CORINFO_EH_CLAUSE_NONE    = 0,   // catch
    CORINFO_EH_CLAUSE_FILTER  = 1,
    CORINFO_EH_CLAUSE_FINALLY = 2,
    CORINFO_EH_CLAUSE_FAULT   = 4,
};

struct CORINFO_EH_CLAUSE {
    DWORD Flags;
    DWORD TryOffset;
    DWORD TryLength;
    DWORD HandlerOffset;
    DWORD HandlerLength;
    DWORD ClassTokenOrFilterOffset;
};

// On x64 Windows there is a single calling convention (the MS x64 ABI), which
// is what both MSVC and MinGW use for a Windows target, and what the CLR uses —
// so no __fastcall/__stdcall annotations are needed or wanted here.

// ICorJitCompiler::compileMethod is vtable slot 0.
typedef int (*CompileMethod_t)(
    void* thisptr, void* comp, CORINFO_METHOD_INFO* info,
    unsigned flags, BYTE** nativeEntry, ULONG* nativeSizeOfCode);

// getJit() exported by clrjit.dll returns ICorJitCompiler*.
typedef void* (*GetJit_t)();

// ICorJitInfo (the `comp` argument) vtable entries used to resolve the token
// and exception info. Their indices are RUNTIME-SPECIFIC and are supplied at
// run time via the ILDUMP_TOKIDX / ILDUMP_EHIDX environment variables, so no
// risky call is made until an index is explicitly provided.
typedef mdToken (*GetMethodDefFromMethod_t)(void* comp, CORINFO_METHOD_HANDLE ftn);
typedef void (*GetEHinfo_t)(void* comp, CORINFO_METHOD_HANDLE ftn,
                            unsigned ehNumber, CORINFO_EH_CLAUSE* clause);
