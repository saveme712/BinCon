#pragma once
#include <cstdint>

#include <iostream>
#include <io.h>
#include <fcntl.h>

#include <Windows.h>

#include <bc_stub.h>
#include <bc_peb.h>
#include <bc_util.h>
#include <bc_thirdparty.h>
#include <bc_integrity.h>
#include <bc_memory.h>
#include <bc_windows.h>
#include <bc_log.h>
#include <bc_pe.h>

#define TIME_BETWEEN_RE_ENCRYPT_CHECKS 5000
#define TIME_BETWEEN_NO_ACCESS_ENCRYPT 30000

namespace bc
{
    struct MappedArea
    {
        uint64_t base = 0;
        uint64_t no_access_time = 0;
        bool no_access = false;
        bool encrypted = false;
        uint64_t decrypt_hits = 0;
    };

    struct StubContext
    {
        packed_app* app = nullptr;
        char* img;
        char* img_all_perms;

        chal_entry cur_chal_entry;

        // PE validators
        pe_validator ntdll_validator;
        pe_validator kernel32_validator;

        CRITICAL_SECTION veh_section;

        HANDLE reencrypt_thread_handle = NULL;

        std::map<uint64_t, MappedArea> mapped_areas;

        struct
        {
            obfuscated_prim64<decltype(TerminateProcess)*, 0x1337, __LINE__> TerminateProcess;
            obfuscated_prim64<decltype(GetCurrentProcessId)*, 0x1337, __LINE__> GetCurrentProcessId;
            obfuscated_prim64<decltype(QueryPerformanceCounter)*, 0x1337, __LINE__> QueryPerformanceCounter;
            obfuscated_prim64<decltype(GetProcAddress)*, 0x1337, __LINE__> GetProcAddress;
            obfuscated_prim64<decltype(VirtualProtect)*, 0x1337, __LINE__> VirtualProtect;
            obfuscated_prim64<decltype(EnterCriticalSection)*, 0x1337, __LINE__> EnterCriticalSection;
            obfuscated_prim64<decltype(LeaveCriticalSection)*, 0x1337, __LINE__> LeaveCriticalSection;
            obfuscated_prim64<decltype(Sleep)*, 0x1337, __LINE__> Sleep;
            obfuscated_prim64<decltype(GetTickCount64)*, 0x1337, __LINE__> GetTickCount64;
            obfuscated_prim64<decltype(SizeofResource)*, 0x1337, __LINE__> SizeofResource;
            obfuscated_prim64<decltype(SetConsoleTextAttribute)*, 0x1337, __LINE__> SetConsoleTextAttribute;
            obfuscated_prim64<decltype(GetCurrentProcess)*, 0x1337, __LINE__> GetCurrentProcess;
            obfuscated_prim64<decltype(GetStdHandle)*, 0x1337, __LINE__> GetStdHandle;
            obfuscated_prim64<decltype(InitializeCriticalSection)*, 0x1337, __LINE__> InitializeCriticalSection;
            obfuscated_prim64<decltype(FindResourceA)*, 0x1337, __LINE__> FindResourceA;
            obfuscated_prim64<decltype(GetModuleHandleA)*, 0x1337, __LINE__> GetModuleHandleA;
            obfuscated_prim64<decltype(LockResource)*, 0x1337, __LINE__> LockResource;
            obfuscated_prim64<decltype(CreateThread)*, 0x1337, __LINE__> CreateThread;
            obfuscated_prim64<decltype(LoadResource)*, 0x1337, __LINE__> LoadResource;
            obfuscated_prim64<decltype(FindResourceW)*, 0x1337, __LINE__> FindResourceW;
            obfuscated_prim64<decltype(AddVectoredExceptionHandler)*, 0x1337, __LINE__> AddVectoredExceptionHandler;
            obfuscated_prim64<decltype(AllocConsole)*, 0x1337, __LINE__> AllocConsole;
            obfuscated_prim64<decltype(SetConsoleTitleW)*, 0x1337, __LINE__> SetConsoleTitleW;
            obfuscated_prim64<decltype(GetModuleHandleW)*, 0x1337, __LINE__> GetModuleHandleW;
            obfuscated_prim64<decltype(SetUnhandledExceptionFilter)*, 0x1337, __LINE__> SetUnhandledExceptionFilter;
            obfuscated_prim64<decltype(GetFileSize)*, 0x1337, __LINE__> GetFileSize;
            obfuscated_prim64<decltype(GetSystemTimeAsFileTime)*, 0x1337, __LINE__> GetSystemTimeAsFileTime;
            obfuscated_prim64<decltype(GetCurrentThread)*, 0x1337, __LINE__> GetCurrentThread;
            obfuscated_prim64<decltype(GetThreadContext)*, 0x1337, __LINE__> GetThreadContext;
            obfuscated_prim64<decltype(SetThreadContext)*, 0x1337, __LINE__> SetThreadContext;
            obfuscated_prim64<decltype(IsDebuggerPresent)*, 0x1337, __LINE__> IsDebuggerPresent;
            obfuscated_prim64<decltype(ReadFile)*, 0x1337, __LINE__> ReadFile;
            obfuscated_prim64<decltype(VirtualFree)*, 0x1337, __LINE__> VirtualFree;
            obfuscated_prim64<decltype(VirtualAlloc)*, 0x1337, __LINE__> VirtualAlloc;
            obfuscated_prim64<decltype(CreateFileA)*, 0x1337, __LINE__> CreateFileA;
            obfuscated_prim64<decltype(LoadLibraryA)*, 0x1337, __LINE__> LoadLibraryA;
            obfuscated_prim64<decltype(GetCurrentThreadId)*, 0x1337, __LINE__> GetCurrentThreadId;


            obfuscated_prim64<decltype(NtMapViewOfSection)*, 0x1337, __LINE__> NtMapViewOfSection;
            obfuscated_prim64<decltype(NtCreateSection)*, 0x1337, __LINE__> NtCreateSection;
        } iat;
    };

    typedef int (*fn_main)(int argc, const char* argv[]);
    typedef void(*fn_main_chal)(chal_entry* ce);

    void free_encrypted(uint64_t addr);
    uint64_t allocate_encrypted(size_t size);
    bool emulate_encrypted_ins(PCONTEXT context, void* ins);
    uint64_t resolve_mem_ref(PCONTEXT context, void* ins);

    void re_encrypt_code();
    void re_encrypt_code_thread();
    LONG decrypt_code_except_handler(_EXCEPTION_POINTERS* exception_info);

    void* hook_get_proc_address(HMODULE m, const char* name);
    HRSRC hook_find_resource(HMODULE m, LPCSTR rsc, LPCSTR type);
    HGLOBAL hook_load_resource(HMODULE m, HRSRC src);
    LPVOID hook_lock_resource(HGLOBAL global);
    DWORD hook_sizeof_resource(HMODULE m, HRSRC src);

    extern StubContext BC;

    extern "C" void disable_tf();

#include "stub.inc"
#include "crt.inc"
#include "load.inc"
#include "veh.inc"
}
