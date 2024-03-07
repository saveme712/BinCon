#pragma once
#include <iostream>
#include <io.h>
#include <fcntl.h>

#include <Windows.h>

#include "stub.h"

#include <bc_stub.h>
#include <bc_peb.h>
#include <bc_util.h>
#include <bc_thirdparty.h>
#include <bc_integrity.h>
#include <bc_windows.h>
#include <bc_log.h>
#include <bc_pe.h>
#include <bc_iat.h>

#include <xorstr.hpp>

namespace bc
{
    /// <summary>
    /// Determines if a thread is still running.
    /// </summary>
    __forceinline bool is_thread_still_running(HANDLE h)
    {
        return WaitForSingleObject(h, 0) != WAIT_TIMEOUT;
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
            auto std_handle = IAT.GetStdHandle(STD_INPUT_HANDLE);
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
            auto std_handle = IAT.GetStdHandle(STD_OUTPUT_HANDLE);
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
            auto std_handle = IAT.GetStdHandle(STD_ERROR_HANDLE);
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
}