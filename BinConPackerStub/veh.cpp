#include "stub.h"

namespace bc
{
    /// <summary>
    /// Re-encrypts all code sections.
    /// </summary>
    void re_encrypt_code()
    {
        disable_tf();
        BC.iat.EnterCriticalSection(&BC.veh_section);

        auto num_pages_total = BC.mapped_areas.size();
        auto num_pages_encrypted = 0;
        auto num_pages_no_access = 0;
        for (auto kv : BC.mapped_areas)
        {
            auto& ma = kv.second;
            if (ma.encrypted)
            {
                num_pages_encrypted += 1;
            }
            
            if (ma.no_access)
            {
                num_pages_no_access += 1;
            }
        }

        auto iimg = (uint64_t)BC.img;
        auto iapp = (uint64_t)BC.app;
        auto sections = (packed_section*)(iapp + BC.app->off_to_sections.off);
        auto time = BC.iat.GetTickCount64();

        INFO("re-encrypting code (" << num_pages_total << ":" << num_pages_encrypted << ":" << num_pages_no_access << ")");
        for (auto& kv : BC.mapped_areas)
        {
            auto& ma = kv.second;
            if (!ma.encrypted)
            {
                auto full_addr = (uint64_t)BC.img + ma.base;
                auto full_addr_perms = (uint64_t)BC.img_all_perms + ma.base;

                if (!ma.no_access)
                {
                    DWORD old_protect;
                    BC.iat.VirtualProtect((void*)full_addr, PAGE_SIZE_4KB, PAGE_NOACCESS, &old_protect);

                    ma.no_access = true;
                    ma.no_access_time = time + TIME_BETWEEN_NO_ACCESS_ENCRYPT;
                }

                if (ma.no_access && time >= ma.no_access_time)
                {
                    obfuscated_byte_array<0x1337, 7> ba((char*)full_addr_perms, PAGE_SIZE_4KB);
                    ba.encrypt();

                    ma.encrypted = true;
                }
            }
        }

        BC.iat.LeaveCriticalSection(&BC.veh_section);
    }


    /// <summary>
    /// A thread while re-encrypts code periodically.
    /// </summary>
    void re_encrypt_code_thread()
    {
        while (TRUE)
        {
            disable_tf();

            Sleep(TIME_BETWEEN_RE_ENCRYPT_CHECKS);
            re_encrypt_code();
        }
    }

    /// <summary>
    /// Attempts to decrypt a section.
    /// </summary>
    static __forceinline bool decrypt_section(uint64_t rip, uint64_t exception_page)
    {
        auto iimg = (uint64_t)BC.img;
        auto iapp = (uint64_t)BC.app;
        auto sections = (packed_section*)(iapp + BC.app->off_to_sections.off);
        DWORD old_protect;

        TRACE("[exception]");
        TRACE(" -> rip: " << std::hex << rip
            << ", img: " << std::hex << iimg);

        for (auto i = 0; i < BC.app->off_to_sections.num_elements; i++)
        {
            auto& section = sections[i];
            auto characteristics = section.characteristics.get();
            TRACE(xorstr_("[section_search]"));
            TRACE(xorstr_(" -> off: ") << std::hex << section.rva.get() << xorstr_(", size: ") << std::hex << section.size_of_data.get() << xorstr_(", char: "));

            if (exception_page >= (iimg + section.rva) &&
                exception_page < ((iimg + section.rva + section.size_of_data)))
            {
                if (characteristics & (uint64_t)packed_section_characteristic::can_lazy_load)
                {
                    auto page_offset = PAGE_ADDR(exception_page) - (iimg + section.rva);

                    auto& ma = BC.mapped_areas[(uint64_t)section.rva + page_offset];
                    auto target_offset = BC.img + section.rva + page_offset;
                    auto target_offset_perms = BC.img_all_perms + section.rva + page_offset;

                    TRACE(xorstr_("[found]"));
                    TRACE(xorstr_(" -> rip: ") << std::hex << exception_page << xorstr_(", off: ") << std::hex << page_offset);

                    if (ma.encrypted)
                    {
                        obfuscated_byte_array<0x1337, 7> ba(target_offset_perms, PAGE_SIZE_4KB);
                        ba.decrypt();

                        ma.encrypted = false;
                    }

                    BC.iat.VirtualProtect(target_offset, PAGE_SIZE_4KB, PAGE_EXECUTE_READWRITE, &old_protect);
                    ma.no_access = false;

                    ma.decrypt_hits += 1;
                    return true;
                }
            }
        }

        return false;
    }

    LONG decrypt_code_except_handler(_EXCEPTION_POINTERS* exception_info)
    {
        BEGIN_VM(__FUNCTION__);

        disable_tf();
        LONG ret = EXCEPTION_CONTINUE_SEARCH;

        auto app_opts = BC.app->options.get();
        auto lazy_load_code = (app_opts & (uint8_t)packed_app_option::lazy_load_code) != 0;

        BC.iat.EnterCriticalSection(&BC.veh_section);

        if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
            exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
        {
            if (exception_info->ExceptionRecord->ExceptionInformation[0] == 0x0 ||
                exception_info->ExceptionRecord->ExceptionInformation[0] == 0x1)
            {
                if (emulate_encrypted_ins(exception_info->ContextRecord, (void*)exception_info->ContextRecord->Rip))
                {
                    ret = EXCEPTION_CONTINUE_EXECUTION;
                }
                else if (lazy_load_code && decrypt_section(resolve_mem_ref(exception_info->ContextRecord, (void*)exception_info->ContextRecord->Rip), exception_info->ExceptionRecord->ExceptionInformation[1]))
                {
                    ret = EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            else if (exception_info->ExceptionRecord->ExceptionInformation[0] == 0x8)
            {
                if (lazy_load_code && decrypt_section(exception_info->ContextRecord->Rip, exception_info->ExceptionRecord->ExceptionInformation[1]))
                {
                    ret = EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }

        BC.iat.LeaveCriticalSection(&BC.veh_section);

        END_VM(__FUNCTION__);
        return ret;
    }
}
