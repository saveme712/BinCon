#include <Windows.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <map>

#include <bc_stub.h>
#include <bc_peb.h>
#include <bc_util.h>
#include <bc_thirdparty.h>
#include <bc_integrity.h>
#include <bc_memory.h>
#include <bc_windows.h>
#include <bc_log.h>
#include <bc_pe.h>

#include <xorstr.hpp>

#include <Zydis/Zydis.h>

namespace bc
{
    typedef int (*fn_main)(int argc, const char* argv[]);
    typedef void(*fn_main_chal)(chal_entry* ce);

    static packed_app* app = nullptr;
    static char* img;
    static chal_entry cur_chal_entry;

    // PE validators
    static pe_validator ntdll_validator;
    static pe_validator kernel32_validator;

    // memory encryption imports
    void free_encrypted(uint64_t addr);
    uint64_t allocate_encrypted(size_t size);
    bool emulate_encrypted_ins(PCONTEXT context, void* ins);

    /// <summary>
    /// Re-encrypts all code sections.
    /// </summary>
    static void re_encrypt_code()
    {
        auto sections = (packed_section*)(img + app->off_to_sections.off);
        auto walker = peb_walker::tib();

        for (auto i = 0; i < app->off_to_sections.num_elements; i++)
        {
            uint64_t characteristics = sections[i].characteristics;
            if (characteristics & (uint64_t)packed_section_characteristic::can_lazy_load)
            {
                VirtualFree(img + sections[i].rva, sections[i].size_of_data, MEM_DECOMMIT);
            }
        }
    }

    /// <summary>
    /// A thread while re-encrypts code periodically.
    /// </summary>
    static void re_encrypt_code_thread()
    {
        while (TRUE)
        {
            re_encrypt_code();
            Sleep(1000);
        }
    }

    /// <summary>
    /// Attempts to decrypt a section.
    /// </summary>
    static bool decrypt_section(uint64_t rip, uint64_t exception_page)
    {
        auto iimg = (uint64_t)img;
        auto begin = (uint64_t)app;
        auto sections = (packed_section*)(begin + app->off_to_sections.off);

        LOG("[exception]");
        LOG("Rip: " << std::hex << rip
            << ", Img: " << std::hex << iimg);

        for (auto i = 0; i < app->off_to_sections.num_elements; i++)
        {
            auto characteristics = sections[i].characteristics.get();
            LOG("[section_search]");
            LOG("Off: " << std::hex << sections[i].rva.get() << ", Size: " << std::hex << sections[i].size_of_data.get() << ", Char: ");

            if (exception_page >= (iimg + sections[i].rva) &&
                exception_page < ((iimg + sections[i].rva + sections[i].size_of_data)))
            {
                if (characteristics & (uint64_t)packed_section_characteristic::can_lazy_load)
                {
                    // this is the aligned offset into the section
                    auto page_offset = PAGE_ADDR(exception_page) - (iimg + sections[i].rva);
                    LOG("[found]");
                    LOG("Rip: " << std::hex << exception_page << ", Off: " << std::hex << page_offset);

                    DWORD old_protect;
                    VirtualAlloc(img + sections[i].rva + page_offset, PAGE_SIZE_4KB, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                    memcpy(img + sections[i].rva + page_offset, (char*)begin + sections[i].off_to_data + page_offset, PAGE_SIZE_4KB);
                    obfuscated_byte_array ba(img + sections[i].rva + page_offset, PAGE_SIZE_4KB);
                    ba.decrypt();

                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
    }

    static LONG decrypt_code_except_handler(_EXCEPTION_POINTERS* exception_info)
    {
        if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
        {
            if (exception_info->ExceptionRecord->ExceptionInformation[0] == 0x0 ||
                exception_info->ExceptionRecord->ExceptionInformation[0] == 0x1)
            {
                if (emulate_encrypted_ins(exception_info->ContextRecord, (void*)exception_info->ContextRecord->Rip))
                {
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            else if (exception_info->ExceptionRecord->ExceptionInformation[0] == 0x8)
            {
                if (decrypt_section(exception_info->ContextRecord->Rip, exception_info->ExceptionRecord->ExceptionInformation[1]))
                {
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    __forceinline void bind_crt_handles_to_std_handles()
    {
        FILE* df_1;
        freopen_s(&df_1, xorstr_("nul"), xorstr_("r"), stdin);

        FILE* df_2;
        freopen_s(&df_2, xorstr_("nul"), xorstr_("w"), stdout);

        FILE* df_3;
        freopen_s(&df_3, xorstr_("nul"), xorstr_("w"), stderr);

        {
            auto std_handle = GetStdHandle(STD_INPUT_HANDLE);
            if (std_handle != INVALID_HANDLE_VALUE)
            {
                auto file_desc = _open_osfhandle((intptr_t)std_handle, _O_TEXT);
                if (file_desc != -1)
                {
                    auto file = _fdopen(file_desc, xorstr_("r"));
                    if (file != NULL)
                    {
                        auto dup2_res = _dup2(_fileno(file), _fileno(stdin));
                        if (dup2_res == 0)
                        {
                            setvbuf(stdin, NULL, _IONBF, 0);
                        }
                    }
                }
            }
        }

        {
            auto std_handle = GetStdHandle(STD_OUTPUT_HANDLE);
            if (std_handle != INVALID_HANDLE_VALUE)
            {
                auto file_desc = _open_osfhandle((intptr_t)std_handle, _O_TEXT);
                if (file_desc != -1)
                {
                    auto file = _fdopen(file_desc, xorstr_("w"));
                    if (file != NULL)
                    {
                        int dup2_res = _dup2(_fileno(file), _fileno(stdout));
                        if (dup2_res == 0)
                        {
                            setvbuf(stdout, NULL, _IONBF, 0);
                        }
                    }
                }
            }
        }

        {
            auto std_handle = GetStdHandle(STD_ERROR_HANDLE);
            if (std_handle != INVALID_HANDLE_VALUE)
            {
                auto file_desc = _open_osfhandle((intptr_t)std_handle, _O_TEXT);
                if (file_desc != -1)
                {
                    auto file = _fdopen(file_desc, xorstr_("w"));
                    if (file != NULL)
                    {
                        auto dup2_res = _dup2(_fileno(file), _fileno(stderr));
                        if (dup2_res == 0)
                        {
                            setvbuf(stderr, NULL, _IONBF, 0);
                        }
                    }
                }
            }
        }

        std::wcin.clear();
        std::cin.clear();

        std::wcout.clear();
        std::cout.clear();

        std::wcerr.clear();
        std::cerr.clear();
    }

    /// <summary>
    /// Our hook for GetProcAddress. This allows us to query packer information without
    /// a custom entry-point.
    /// </summary>
    static void* hook_get_proc_address(HMODULE m, const char* name)
    {
        if (m == (HMODULE)0xBC && !strcmp(name, xorstr_("pack_interface")))
        {
            return &cur_chal_entry;
        }

        return GetProcAddress(m, name);
    }
    
    /// <summary>
    /// Maps the custom image format into the memory of this process as a some-what valid PE image.
    /// </summary>
    __forceinline void* map()
    {
        auto begin = (uint64_t)app;
        auto sections = (packed_section*)(begin + app->off_to_sections.off);
        auto imports = (packed_import*)(begin + app->off_to_iat.off);
        auto relocs = (packed_reloc*)(begin + app->off_to_relocs.off);
        auto walker = peb_walker::tib();

        img = (char*)VirtualAlloc(NULL, app->size_of_img, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        for (auto i = 0; i < app->off_to_sections.num_elements; i++)
        {
            uint64_t characteristics = sections[i].characteristics; 
            if (characteristics & (uint64_t)packed_section_characteristic::can_lazy_load)
            {
                VirtualFree(img + sections[i].rva, sections[i].size_of_data, MEM_DECOMMIT);
            }
            else
            {
                obfuscated_byte_array ba((char*)begin + sections[i].off_to_data, sections[i].size_of_data);
                ba.decrypt();

                memcpy(img + sections[i].rva, (char*)begin + sections[i].off_to_data, sections[i].size_of_data);
                ba.encrypt();
            }
        }

        for (auto i = 0; i < app->off_to_iat.num_elements; i++)
        {
            auto& import = imports[i];

            wchar_t module_name_wide[256];

            char module_name[256];
            import.mod.get(module_name);

            ascii_to_wide(module_name, module_name_wide);

            auto llw = (decltype(LoadLibraryW)*)walker.resolve_function(xorstr_(L"Kernel32.dll"), xorstr_("LoadLibraryW"));
            auto gpa = (decltype(GetProcAddress)*)walker.resolve_function(xorstr_(L"Kernel32.dll"), xorstr_("GetProcAddress"));
            auto module = llw(module_name_wide);

            uint64_t resolved = 0;
            switch (import.type)
            {
            case packed_import_type::name:
            {
                char dec_name[256];
                import.name.get(dec_name);

                resolved = (uint64_t)walker.resolve_function(module_name_wide, dec_name);
                if (!resolved)
                {
                    resolved = (uint64_t)gpa(module, dec_name);
                }

                *((uint64_t*)(img + import.rva)) = resolved;
                break;
            }
            case packed_import_type::ordinal:
                resolved = (uint64_t)gpa(module, MAKEINTRESOURCEA(import.ordinal.get()));
                *((uint64_t*)(img + import.rva)) = resolved;
                break;
            default:
                break;
            }

            if (!resolved)
            {
                // TODO FIXME errors
            }
            else if (*((uint64_t*)(img + import.rva)) == (uint64_t)GetProcAddress)
            {
#ifdef DEBUG_LOGGING
                std::cout << "[info] hooked GetProcAddress" << std::endl;
#endif
                *((uint64_t*)(img + import.rva)) = (uint64_t)hook_get_proc_address;
            }
        }

        auto delta = (uint64_t)img - (uint64_t)app->preferred_base;
        for (auto i = 0; i < app->off_to_relocs.num_elements; i++)
        {
            *((uint64_t*)(img + relocs[i].rva)) += delta;
        }

        return img;
    }

    static void verify_anti_debug_pack(fn_integrity_check_failed on_fail)
    {
        if (!ntdll_validator.validate((void*)GetModuleHandleA(xorstr_("ntdll.dll"))))
        {
            on_fail(bc_error::bad_module_checksum);
        }

        if (!kernel32_validator.validate((void*)GetModuleHandleA(xorstr_("kernel32.dll"))))
        {
            on_fail(bc_error::bad_module_checksum);
        }

        if (has_option(app, packed_app_option::anti_debug))
        {
            verify_anti_debug(on_fail);
        }
    }

    void run()
    {
        BEGIN_VM(__FUNCTION__);

        auto rsc = FindResource(NULL, xorstr_(L"p"), RT_RCDATA);
        auto rsc_size = SizeofResource(NULL, rsc);
        auto rsc_data = ::LoadResource(NULL, rsc);
        auto rsc_bin = ::LockResource(rsc_data);
        auto copy = malloc(rsc_size);
        memcpy(copy, rsc_bin, rsc_size);
        UnlockResource(rsc_data);
        
        app = (packed_app*)copy;

        if (has_option(app, packed_app_option::console))
        {
            if (AllocConsole())
            {
                SetConsoleTitle(xorstr_(L"BinCon"));
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                bind_crt_handles_to_std_handles();
            }
        }

        LOG("Adding VEH");
        AddVectoredExceptionHandler(TRUE, decrypt_code_except_handler);

        if (has_option(app, packed_app_option::anti_debug))
        {
            LOG("Installing anti-debug");
            install_anti_debug();
        }

        LOG("Creating PE validators");
        ntdll_validator = pe_validator::map(GetModuleHandleA(xorstr_("ntdll.dll")));
        kernel32_validator = pe_validator::map(GetModuleHandleA(xorstr_("kernel32.dll")));

        LOG("Mapping");
        auto mapped = map();

        LOG("Generating chal entry");
        cur_chal_entry = gen_chal_entry();
        cur_chal_entry.re_encrypt_code = re_encrypt_code;
        cur_chal_entry.alloc_enc = (fn_alloc_encrypted)allocate_encrypted;
        cur_chal_entry.free_enc = (fn_free_encrypted)free_encrypted;
        cur_chal_entry.verify_anti_debug = verify_anti_debug_pack;

        LOG("Creating re-entry code thread");
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)re_encrypt_code_thread, NULL, 0, NULL);

        LOG("Calling main @ " << std::hex << ((uint64_t)mapped + app->ep));
        if (has_option(app, packed_app_option::chal_entry))
        {
            ((fn_main_chal)((uint64_t)mapped + app->ep))(&cur_chal_entry);
        }
        else
        {
            const char* args[2] =
            {
                "BinCon",
                "Packer"
            };

            ((fn_main)((uint64_t)mapped + app->ep))(0, NULL);
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

