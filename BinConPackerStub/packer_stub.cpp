#include "stub.h"
#include "crt.h"
#include "load.h"

#include <cstdint>
#include <Windows.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <map>
#include <tlhelp32.h>

#include <bc_iat.h>

#include <xorstr.hpp>

#include <Zydis/Zydis.h>

namespace bc
{
    StubContext BC;

    static void verify_anti_debug_pack(fn_integrity_check_failed on_fail)
    {
        disable_tf();

        auto app_opts = BC.app->options.get();
        auto lazy_load_code = (app_opts & (uint8_t)packed_app_option::lazy_load_code) != 0;

        if (!BC.ntdll_validator.validate((void*)GetModuleHandleA(xorstr_("ntdll.dll"))))
        {
            on_fail(bc_error::bad_module_checksum);
        }

        if (!BC.kernel32_validator.validate((void*)GetModuleHandleA(xorstr_("kernel32.dll"))))
        {
            on_fail(bc_error::bad_module_checksum);
        }

        if (lazy_load_code && !is_thread_still_running(BC.reencrypt_thread_handle))
        {
            on_fail(bc_error::reencrypt_thread_not_running);
        }

        if (has_option(BC.app, packed_app_option::anti_debug))
        {
            verify_anti_debug(on_fail);
        }
    }

    void run()
    {
        BEGIN_VM(__FUNCTION__);
        IAT.InitializeCriticalSection(&BC.veh_section);

        auto rsc = IAT.FindResourceW(NULL, xorstr_(L"p"), RT_RCDATA);
        auto rsc_size = IAT.SizeofResource(NULL, rsc);
        auto rsc_data = IAT.LoadResource(NULL, rsc);
        auto rsc_bin = IAT.LockResource(rsc_data);
        auto copy = malloc(rsc_size);
        memcpy(copy, rsc_bin, rsc_size);
        UnlockResource(rsc_data);
        
        BC.app = (packed_app*)copy;

        if (has_option(BC.app, packed_app_option::console))
        {
            if (AllocConsole())
            {
                IAT.SetConsoleTitleW(xorstr_(L"BinCon"));
                IAT.SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                bind_crt_handles_to_std_handles();
            }
        }

        INFO("Adding VEH");
        IAT.AddVectoredExceptionHandler(TRUE, decrypt_code_except_handler);

        if (has_option(BC.app, packed_app_option::anti_debug))
        {
            INFO("Installing anti-debug");
            install_anti_debug();
        }

        INFO("Creating PE validators");
        BC.ntdll_validator = pe_validator::map(IAT.GetModuleHandleA(xorstr_("ntdll.dll")));
        BC.kernel32_validator = pe_validator::map(IAT.GetModuleHandleA(xorstr_("kernel32.dll")));

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
            BC.reencrypt_thread_handle = IAT.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)re_encrypt_code_thread, NULL, 0, NULL);
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
    bc::init_iat();
    bc::run();
    return 0;
}

