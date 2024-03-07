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

#define TIME_BETWEEN_RE_ENCRYPT_CHECKS 1000
#define TIME_BETWEEN_NO_ACCESS_ENCRYPT 7000

namespace bc
{
    struct MappedArea
    {
        uint64_t base = 0;
        uint64_t no_access_time = 0;
        uint64_t decrypt_hits = 0;
        bool no_access = false;
        bool encrypted = false;
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
}