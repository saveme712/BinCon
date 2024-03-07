#pragma once
#include <bc_iat.h>

namespace bc
{
    /// <summary>
    /// Maps the custom image format into the memory of this process as a some-what valid PE image.
    /// </summary>
    static __forceinline void* map()
    {
        auto begin = (uint64_t)BC.app;
        auto sections = (packed_section*)(begin + BC.app->off_to_sections.off);
        auto imports = (packed_import*)(begin + BC.app->off_to_iat.off);
        auto relocs = (packed_reloc*)(begin + BC.app->off_to_relocs.off);
        auto walker = peb_walker::tib();

        HANDLE section;

        LARGE_INTEGER section_size;
        section_size.QuadPart = BC.app->size_of_img.get();

        LARGE_INTEGER section_offset = { 0 };
        SIZE_T section_view_size = 0;
        void* section_view_base = NULL;

        LOG(xorstr_("Size of img: ") << std::hex << BC.app->size_of_img.get());

        IAT.NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

        IAT.NtMapViewOfSection(section, IAT.GetCurrentProcess(), &section_view_base, 0, BC.app->size_of_img, &section_offset, &section_view_size, ViewUnmap, 0, PAGE_READWRITE);
        BC.img_all_perms = (char*)section_view_base;

        section_view_base = NULL;
        section_offset = { 0 };
        section_view_size = 0;

        IAT.NtMapViewOfSection(section, IAT.GetCurrentProcess(), &section_view_base, 0, BC.app->size_of_img, &section_offset, &section_view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
        BC.img = (char*)section_view_base;

        LOG("Setting image to zero");
        memset(BC.img, 0, BC.app->size_of_img);

        LOG("Filling in headers");
        memcpy(BC.img, (char*)begin + BC.app->off_to_headers.off.get(), BC.app->off_to_headers.num_elements.get());

        LOG("Filling in sections");
        for (auto i = 0; i < BC.app->off_to_sections.num_elements; i++)
        {
            obfuscated_byte_array<0x1337, 7> ba((char*)begin + sections[i].off_to_data.get(), sections[i].size_of_data.get());
            ba.decrypt();

            memcpy(BC.img + sections[i].rva, (char*)begin + sections[i].off_to_data.get(), sections[i].size_of_data.get());
            ba.encrypt();
        }

        LOG("Patching deltas");
        auto delta = (uint64_t)BC.img - (uint64_t)BC.app->preferred_base;
        for (auto i = 0ull; i < BC.app->off_to_relocs.num_elements; i++)
        {
            *((uint64_t*)(BC.img + relocs[i].rva)) += delta;
        }

        LOG("Filling in imports");
        for (auto i = 0ull; i < BC.app->off_to_iat.num_elements; i++)
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

                LOG("[info] import " << std::hex << (uint64_t)BC.img << " " << import.rva.get() << " " << dec_name << " " << resolved);
                *((uint64_t*)(BC.img + import.rva)) = resolved;
                break;
            }
            case packed_import_type::ordinal:
                LOG("[info] import ordinal " << import.ordinal.get());
                resolved = (uint64_t)gpa(module, MAKEINTRESOURCEA(import.ordinal.get()));
                *((uint64_t*)(BC.img + import.rva)) = resolved;
                break;
            default:
                break;
            }

            if (!resolved)
            {
                ERR("Failed to get proc address " << module_name);
            }
            else if (*((uint64_t*)(BC.img + import.rva)) == (uint64_t)IAT.GetProcAddress.get())
            {
                LOG("[info] hooked GetProcAddress");
                *((uint64_t*)(BC.img + import.rva)) = (uint64_t)hook_get_proc_address;
            }
            else if (*((uint64_t*)(BC.img + import.rva)) == (uint64_t)IAT.FindResourceA.get() ||
                     *((uint64_t*)(BC.img + import.rva)) == (uint64_t)IAT.FindResourceW.get())
            {
                LOG("[info] hooked FindResource");
                *((uint64_t*)(BC.img + import.rva)) = (uint64_t)hook_find_resource;
            }
            else if (*((uint64_t*)(BC.img + import.rva)) == (uint64_t)IAT.LoadResource.get())
            {
                LOG("[info] hooked LoadResource");
                *((uint64_t*)(BC.img + import.rva)) = (uint64_t)hook_load_resource;
            }
            else if (*((uint64_t*)(BC.img + import.rva)) == (uint64_t)IAT.LockResource.get())
            {
                LOG("[info] hooked LockResource");
                *((uint64_t*)(BC.img + import.rva)) = (uint64_t)hook_lock_resource;
            }
            else if (*((uint64_t*)(BC.img + import.rva)) == (uint64_t)IAT.SizeofResource.get())
            {
                LOG("[info] hooked SizeofResource");
                *((uint64_t*)(BC.img + import.rva)) = (uint64_t)hook_sizeof_resource;
            }
        }

        if (has_option(BC.app, packed_app_option::lazy_load_code))
        {
            LOG("Guarding memory");
            for (auto i = 0; i < BC.app->off_to_sections.num_elements; i++)
            {
                uint64_t characteristics = sections[i].characteristics;
                if (characteristics & (uint64_t)packed_section_characteristic::can_lazy_load)
                {
                    DWORD old_protect;
                    IAT.VirtualProtect(BC.img + sections[i].rva, sections[i].size_of_data, PAGE_NOACCESS, &old_protect);

                    obfuscated_byte_array<0x1337, 7> ba((char*)BC.img_all_perms + sections[i].rva, sections[i].size_of_data);
                    ba.encrypt();

                    for (auto j = 0ull; j < sections[i].size_of_data / PAGE_SIZE_4KB; j++)
                    {
                        MappedArea area;
                        area.base = sections[i].rva + (j * PAGE_SIZE_4KB);
                        area.encrypted = true;

                        BC.mapped_areas[area.base] = area;
                    }
                }
            }
        }

        return BC.img;
    }
}