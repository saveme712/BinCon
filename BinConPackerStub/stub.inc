#pragma once
/// <summary>
/// Finds a section by a relative virtual address.
/// </summary>
static __forceinline bc::packed_section* section_by_rva(uint64_t rva)
{
    auto iimg = (uint64_t)BC.img;
    auto begin = (uint64_t)BC.app;
    auto sections = (packed_section*)(begin + BC.app->off_to_sections.off);

    for (auto i = 0; i < BC.app->off_to_sections.num_elements; i++)
    {
        auto& section = sections[i];
        if (rva >= section.rva && rva < (section.rva + section.size_of_data))
        {
            return &section;
        }
    }

    return NULL;
}
