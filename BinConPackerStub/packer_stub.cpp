#include <Windows.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <io.h>
#include <fcntl.h>

#include <bc_stub.h>
#include <bc_peb.h>
#include <bc_util.h>
#include <bc_thirdparty.h>
#include <bc_integrity.h>
#include <bc_memory.h>
#include <bc_windows.h>

#include <xorstr.hpp>

namespace bc
{
    typedef int (*fn_main)(int argc, const char* argv[]);
    typedef void(*fn_main_chal)(chal_entry* ce);

    static packed_app* app = nullptr;
    static char* img;

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

    static LONG decrypt_code_except_handler(_EXCEPTION_POINTERS* exception_info)
    {
        auto rip = exception_info->ContextRecord->Rip;
        auto iimg = (uint64_t)img;
        auto begin = (uint64_t)app;
        auto sections = (packed_section*)(begin + app->off_to_sections.off);

        if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
            exception_info->ExceptionRecord->ExceptionInformation[0] == 0x8)
        {
#ifdef DEBUG_LOGGING
            std::cout << "[exception]" << std::endl;
            std::cout
                << "Reason: " << std::hex << exception_info->ExceptionRecord->ExceptionCode
                << ", Addr: " << std::hex << exception_info->ExceptionRecord->ExceptionAddress
                << ", Info: " << std::hex << exception_info->ExceptionRecord->ExceptionInformation[0]
                << ", Info: " << std::hex << exception_info->ExceptionRecord->ExceptionInformation[1]
                << ", Info: " << std::hex << exception_info->ExceptionRecord->ExceptionInformation[2]
                << std::endl;

            std::cout
                << "Rip: " << std::hex << rip
                << ", Img: " << std::hex << iimg << std::endl;
#endif

            auto exception_page = exception_info->ExceptionRecord->ExceptionInformation[1];
            for (auto i = 0; i < app->off_to_sections.num_elements; i++)
            {
                uint64_t characteristics = sections[i].characteristics;
#ifdef DEBUG_LOGGING
                std::cout << "[section_search]" << std::endl;
                std::cout
                    << "Off: " << std::hex << sections[i].rva.get()
                    << ", Size: " << std::hex << sections[i].size_of_data.get()
                    << ", Char: " << std::hex << characteristics
                    << std::endl;
#endif

                if (exception_page >= (iimg + sections[i].rva) &&
                    exception_page < ((iimg + sections[i].rva + sections[i].size_of_data)))
                {
                    if (characteristics & (uint64_t)packed_section_characteristic::can_lazy_load)
                    {
                        // this is the aligned offset into the section
                        auto page_offset = PAGE_ADDR(exception_page) - (iimg + sections[i].rva);
#ifdef DEBUG_LOGGING
                        std::cout << "[found]" << std::endl;
                        std::cout
                            << "Rip: " << std::hex << exception_page
                            << ", Off: " << std::hex << page_offset
                            << std::endl;
#endif

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

        return EXCEPTION_CONTINUE_SEARCH;
    }

    __forceinline void bind_crt_handles_to_std_handles()
    {
        FILE* df_1;
        freopen_s(&df_1, "nul", "r", stdin);

        FILE* df_2;
        freopen_s(&df_2, "nul", "w", stdout);

        FILE* df_3;
        freopen_s(&df_3, "nul", "w", stderr);

        {
            auto std_handle = GetStdHandle(STD_INPUT_HANDLE);
            if (std_handle != INVALID_HANDLE_VALUE)
            {
                auto file_desc = _open_osfhandle((intptr_t)std_handle, _O_TEXT);
                if (file_desc != -1)
                {
                    auto file = _fdopen(file_desc, "r");
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
                    auto file = _fdopen(file_desc, "w");
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
                    auto file = _fdopen(file_desc, "w");
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

    __forceinline std::vector<char> read_file(const std::string& name)
    {
        std::ifstream f(name, std::ios_base::binary);
        return std::vector<char>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }

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
        }

        auto delta = (uint64_t)img - (uint64_t)app->preferred_base;
        for (auto i = 0; i < app->off_to_relocs.num_elements; i++)
        {
            *((uint64_t*)(img + relocs[i].rva)) += delta;
        }

        return img;
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
        if (has_option(app, packed_app_option::lazy_load_code))
        {
            AddVectoredExceptionHandler(TRUE, decrypt_code_except_handler);
        }

        if (has_option(app, packed_app_option::anti_debug))
        {
            install_anti_debug();
        }

        if (has_option(app, packed_app_option::console))
        {
            if (AllocConsole())
            {
                SetConsoleTitle(xorstr_(L"BinCon"));
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                bind_crt_handles_to_std_handles();
            }
        }

        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)re_encrypt_code_thread, NULL, 0, NULL);

#ifdef DEBUG_LOGGING
        std::cout << "Mapping" << std::endl;
        std::cin.get();
#endif
        auto mapped = map();

#ifdef DEBUG_LOGGING
        std::cout << "Calling main @ " << std::hex << ((uint64_t)mapped + app->ep) << std::endl;
        std::cin.get();
#endif
        if (has_option(app, packed_app_option::chal_entry))
        {
            auto entry = gen_chal_entry();
            entry.re_encrypt_code = re_encrypt_code;

            ((fn_main_chal)((uint64_t)mapped + app->ep))(&entry);
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
    bc::run();
    return 0;
}

