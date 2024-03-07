#pragma once

namespace bc
{
    /// <summary>
    /// Finds a section by a relative virtual address.
    /// </summary>
    static __forceinline bc::packed_section* section_by_rva(uint64_t rva)
    {
        auto begin = (uint64_t)BC.app;
        auto sections = (packed_section*)(begin + BC.app->off_to_sections.off);

        for (auto i = 0ull; i < BC.app->off_to_sections.num_elements.get(); i++)
        {
            auto& section = sections[i];
            if (rva >= section.rva && rva < (section.rva + section.size_of_data))
            {
                return &section;
            }
        }

        return NULL;
    }
}