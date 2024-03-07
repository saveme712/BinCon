#include "stub.h"

#include <cstdint>
#include <Windows.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <map>
#include <tlhelp32.h>

#include <xorstr.hpp>

#include <Zydis/Zydis.h>

namespace bc
{
    StubContext BC;

    static void verify_anti_debug_pack(fn_integrity_check_failed on_fail)
    {
        disable_tf();

        if (!BC.ntdll_validator.validate((void*)GetModuleHandleA(xorstr_("ntdll.dll"))))
        {
            on_fail(bc_error::bad_module_checksum);
        }

        if (!BC.kernel32_validator.validate((void*)GetModuleHandleA(xorstr_("kernel32.dll"))))
        {
            on_fail(bc_error::bad_module_checksum);
        }

        if (has_option(BC.app, packed_app_option::anti_debug))
        {
            verify_anti_debug(on_fail);
        }
    }

    __forceinline void init_iat()
    {
        auto peb = peb_walker::tib();

        auto kernel32 = (char*)peb.resolve_module(xorstr_(L"kernel32.dll"));
        auto ntdll = (char*)peb.resolve_module(xorstr_(L"ntdll.dll"));
#define FILL_IAT(M, N) iat.N = (decltype(N)*)peb.resolve_function(M, xorstr_(#N));

        auto& iat = BC.iat;


        FILL_IAT(kernel32, TerminateProcess); //TerminateProcess;
        FILL_IAT(kernel32, GetCurrentProcessId); //GetCurrentProcessId;
        FILL_IAT(kernel32, QueryPerformanceCounter); //QueryPerformanceCounter;
        FILL_IAT(kernel32, GetProcAddress); //GetProcAddress;
        FILL_IAT(kernel32, VirtualProtect); //VirtualProtect;
        FILL_IAT(kernel32, EnterCriticalSection); //EnterCriticalSection;
        FILL_IAT(kernel32, LeaveCriticalSection); //LeaveCriticalSection;
        FILL_IAT(kernel32, Sleep); //Sleep;
        FILL_IAT(kernel32, GetTickCount64); //GetTickCount64;
        FILL_IAT(kernel32, SizeofResource); //SizeofResource;
        FILL_IAT(kernel32, SetConsoleTextAttribute); //SetConsoleTextAttribute;
        FILL_IAT(kernel32, GetCurrentProcess); //GetCurrentProcess;
        FILL_IAT(kernel32, GetStdHandle); //GetStdHandle;
        FILL_IAT(kernel32, InitializeCriticalSection); //InitializeCriticalSection;
        FILL_IAT(kernel32, FindResourceA); //FindResourceA;
        FILL_IAT(kernel32, GetModuleHandleA); //GetModuleHandleA;
        FILL_IAT(kernel32, LockResource); //LockResource;
        FILL_IAT(kernel32, CreateThread); //CreateThread;
        FILL_IAT(kernel32, LoadResource); //LoadResource;
        FILL_IAT(kernel32, FindResourceW); //FindResourceW;
        FILL_IAT(kernel32, AddVectoredExceptionHandler); //AddVectoredExceptionHandler;
        FILL_IAT(kernel32, AllocConsole); //AllocConsole;
        FILL_IAT(kernel32, SetConsoleTitleW); //SetConsoleTitleW;
        FILL_IAT(kernel32, GetModuleHandleW); //GetModuleHandleW;
        FILL_IAT(kernel32, SetUnhandledExceptionFilter); //SetUnhandledExceptionFilter;
        FILL_IAT(kernel32, GetFileSize); //GetFileSize;
        FILL_IAT(kernel32, GetSystemTimeAsFileTime); //GetSystemTimeAsFileTime;
        FILL_IAT(kernel32, GetCurrentThread); //GetCurrentThread;
        FILL_IAT(kernel32, GetThreadContext); //GetThreadContext;
        FILL_IAT(kernel32, SetThreadContext); //SetThreadContext;
        FILL_IAT(kernel32, IsDebuggerPresent); //IsDebuggerPresent;
        FILL_IAT(kernel32, ReadFile); //ReadFile;
        FILL_IAT(kernel32, VirtualFree); //VirtualFree;
        FILL_IAT(kernel32, VirtualAlloc); //VirtualAlloc;
        FILL_IAT(kernel32, CreateFileA); //CreateFileA;
        FILL_IAT(kernel32, LoadLibraryA); //LoadLibraryA;
        FILL_IAT(kernel32, GetCurrentThreadId);

        FILL_IAT(ntdll, NtMapViewOfSection);
        FILL_IAT(ntdll, NtCreateSection);
    }

    void run()
    {
        BEGIN_VM(__FUNCTION__);

        init_iat();
        BC.iat.InitializeCriticalSection(&BC.veh_section);

        auto rsc = BC.iat.FindResourceW(NULL, xorstr_(L"p"), RT_RCDATA);
        auto rsc_size = BC.iat.SizeofResource(NULL, rsc);
        auto rsc_data = BC.iat.LoadResource(NULL, rsc);
        auto rsc_bin = BC.iat.LockResource(rsc_data);
        auto copy = malloc(rsc_size);
        memcpy(copy, rsc_bin, rsc_size);
        UnlockResource(rsc_data);
        
        BC.app = (packed_app*)copy;

        if (has_option(BC.app, packed_app_option::console))
        {
            if (AllocConsole())
            {
                BC.iat.SetConsoleTitleW(xorstr_(L"BinCon"));
                BC.iat.SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                bind_crt_handles_to_std_handles();
            }
        }

        if (has_option(BC.app, packed_app_option::lazy_load_code))
        {
            INFO("Adding VEH");
            BC.iat.AddVectoredExceptionHandler(TRUE, decrypt_code_except_handler);
        }

        if (has_option(BC.app, packed_app_option::anti_debug))
        {
            INFO("Installing anti-debug");
            install_anti_debug();
        }

        INFO("Creating PE validators");
        BC.ntdll_validator = pe_validator::map(BC.iat.GetModuleHandleA(xorstr_("ntdll.dll")));
        BC.kernel32_validator = pe_validator::map(BC.iat.GetModuleHandleA(xorstr_("kernel32.dll")));

        INFO("Mapping");
        auto mapped = map();

        INFO("Generating chal entry");
        BC.cur_chal_entry = gen_chal_entry();
        BC.cur_chal_entry.re_encrypt_code = re_encrypt_code;
        BC.cur_chal_entry.alloc_enc = (fn_alloc_encrypted)allocate_encrypted;
        BC.cur_chal_entry.free_enc = (fn_free_encrypted)free_encrypted;
        BC.cur_chal_entry.verify_anti_debug = verify_anti_debug_pack;

        if (has_option(BC.app, packed_app_option::lazy_load_code))
        {
            INFO("Creating re-entry code thread");
            BC.reencrypt_thread_handle = BC.iat.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)re_encrypt_code_thread, NULL, 0, NULL);
        }

        INFO("Calling main @ " << std::hex << ((uint64_t)mapped + BC.app->ep));
        if (has_option(BC.app, packed_app_option::chal_entry))
        {
            ((fn_main_chal)((uint64_t)mapped + BC.app->ep))(&BC.cur_chal_entry);
        }
        else
        {
            const char* args[2] =
            {
                "BinCon",
                "Packer"
            };

            ((fn_main)((uint64_t)mapped + BC.app->ep))(2, args);
        }

        END_VM(__FUNCTION__);
    }
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    bc::init_crc32_table();
    bc::run();
    return 0;
}

