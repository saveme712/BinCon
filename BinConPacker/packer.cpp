#include <iostream>
#include <vector>
#include <istream>
#include <fstream>
#include <Windows.h>
#include <iostream>

#include <bc_stub.h>

namespace bc
{
    std::vector<char> read_file(const std::string& name)
    {
        std::ifstream f(name, std::ios_base::binary);
        return std::vector<char>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }

	uint64_t rva_to_fva(PIMAGE_NT_HEADERS nt, uint64_t rva)
	{
		auto sect = IMAGE_FIRST_SECTION(nt);
		for (auto i = 0; i < nt->FileHeader.NumberOfSections; i++, sect++)
		{
			if (rva >= sect->VirtualAddress && rva < (sect->VirtualAddress + sect->SizeOfRawData))
			{
				return rva - sect->VirtualAddress + sect->PointerToRawData;
			}
		}

		std::cout << "[error] failed to resolve rva to fva " << std::hex << rva << std::endl;
		return 0;
	}

	uint64_t fva_to_rva(PIMAGE_NT_HEADERS nt, uint64_t fva)
	{
		auto sect = IMAGE_FIRST_SECTION(nt);
		for (auto i = 0; i < nt->FileHeader.NumberOfSections; i++, sect++)
		{
			if (fva >= sect->PointerToRawData && fva < (sect->PointerToRawData + sect->SizeOfRawData))
			{
				return fva - sect->PointerToRawData + sect->VirtualAddress;
			}
		}

		std::cout << "[error] failed to resolve fva to rva " << std::hex << fva << std::endl;
		return 0;
	}

	class byte_allocator
	{
	public:
		void* img = nullptr;
		size_t cur_size = 0;

	public:
		byte_allocator(size_t size)
		{
			img = malloc(size);
			memset(img, 0, size);
		}

	public:
		template <typename T>
		T* append(size_t amount)
		{
			auto ret = (char*)img + cur_size;
			cur_size += amount;
			return (T*)ret;
		}

		uint64_t off(void* v)
		{
			return (uint64_t)v - (uint64_t)img;
		}
	};

    void pack(char* input)
    {
        auto read = read_file(input);
        auto dos = (PIMAGE_DOS_HEADER)(read.data());
        auto nt = (PIMAGE_NT_HEADERS)(read.data() + dos->e_lfanew);

		std::cout << "[info] calculating image size" << std::endl;

		auto reloc_count = 0;
		auto sect_size = 0;
		auto import_count = 0;
		if (auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		{
			auto base_reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			auto reloc = (PIMAGE_BASE_RELOCATION)(read.data() + rva_to_fva(nt, rva));

			for (auto cs = 0UL; cs < base_reloc_dir.Size;)
			{
				auto num_relocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto reloc_data = (PUINT16)((PCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION));

				reloc_count += num_relocs;
				reloc_data += num_relocs;

				cs += reloc->SizeOfBlock;
				reloc = (PIMAGE_BASE_RELOCATION)reloc_data;
			}
		}

		auto sect = IMAGE_FIRST_SECTION(nt);
		for (auto i = 0; i < nt->FileHeader.NumberOfSections; i++, sect++)
		{
			sect_size += sect->SizeOfRawData;
		}

		if (auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		{
			auto iat_desc = (PIMAGE_IMPORT_DESCRIPTOR)((UINT64)read.data() + rva_to_fva(nt, rva));
			for (; iat_desc->FirstThunk; ++iat_desc)
			{
				if (auto fthunk = iat_desc->FirstThunk)
				{
					auto thunk = (PIMAGE_THUNK_DATA)((UINT64)read.data() + rva_to_fva(nt, fthunk));
					while (thunk->u1.AddressOfData)
					{
						import_count += 1;
						thunk += 1;
					}
				}
			}
		}

        auto size_of_img =
            sizeof(packed_app) +
            (nt->FileHeader.NumberOfSections * sizeof(packed_section)) +
			(reloc_count * sizeof(packed_reloc)) +
			(import_count * sizeof(packed_import)) +
			sect_size;

		std::cout << "image_data" << std::endl;
		std::cout << " section_count= " << nt->FileHeader.NumberOfSections << std::endl;
		std::cout << " reloc_count= " << reloc_count << std::endl;
		std::cout << " import_count= " << import_count << std::endl;
		std::cout << " size_of_img= " << size_of_img << std::endl;

		std::cout << "[info] building headers" << std::endl;

		byte_allocator allocator(size_of_img);
		auto app = allocator.append<packed_app>(sizeof(packed_app));

		auto sections = allocator.append<packed_section>(nt->FileHeader.NumberOfSections * sizeof(packed_section));
		auto imports = allocator.append<packed_import>(import_count * sizeof(packed_import));
		auto relocs = allocator.append<packed_reloc>(reloc_count * sizeof(packed_reloc));

		std::cout << "huh? " << (uint64_t)app->options.get() << std::endl;
		app->options |= (uint8_t)packed_app_option::console;
		std::cout << "huh? " << (uint64_t)app->options.get() << std::endl;

		app->ep = nt->OptionalHeader.AddressOfEntryPoint;
		app->size_of_img = nt->OptionalHeader.SizeOfImage;
		app->preferred_base = nt->OptionalHeader.ImageBase;

		app->off_to_sections.num_elements = nt->FileHeader.NumberOfSections;
		app->off_to_sections.off = allocator.off(sections);

		app->off_to_relocs.num_elements = reloc_count;
		app->off_to_relocs.off = allocator.off(relocs);

		app->off_to_iat.num_elements = import_count;
		app->off_to_iat.off = allocator.off(imports);

		std::cout << "[info] building sections" << std::endl;
		sect = IMAGE_FIRST_SECTION(nt);
		for (auto i = 0; i < nt->FileHeader.NumberOfSections; i++, sect++)
		{
			sections[i].size_of_data = sect->SizeOfRawData;
			sections[i].rva = sect->VirtualAddress;

			auto section = allocator.append<void>(sect->SizeOfRawData);
			memcpy(section, read.data() + sect->PointerToRawData, sect->SizeOfRawData);

			sections[i].off_to_data = allocator.off(section);
		}

		std::cout << "[info] building relocations" << std::endl;
		if (auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		{
			auto base_reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			auto reloc = (PIMAGE_BASE_RELOCATION)((UINT64)read.data() + rva_to_fva(nt, rva));
			auto reloc_ptr = 0;

			for (auto cs = 0UL; cs < base_reloc_dir.Size;)
			{
				auto reloc_count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto reloc_data = (PUINT16)((PCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION));

				for (auto i = 0UL; i < reloc_count; ++i, ++reloc_data)
				{
					auto data = *reloc_data;
					auto type = data >> 12;
					auto offset = data & 0xFFF;

					relocs[reloc_ptr].rva = reloc->VirtualAddress + offset;
					reloc_ptr += 1;
				}

				cs += reloc->SizeOfBlock;
				reloc = (PIMAGE_BASE_RELOCATION)reloc_data;
			}
		}

		std::cout << "[info] building imports" << std::endl;
		if (auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		{
			auto import_ptr = 0;
			auto iat_desc = (PIMAGE_IMPORT_DESCRIPTOR)((UINT64)read.data() + rva_to_fva(nt, rva));
			for (; iat_desc->FirstThunk; ++iat_desc)
			{
				auto module_name = read.data() + rva_to_fva(nt, iat_desc->Name);
				if (auto fthunk = iat_desc->FirstThunk)
				{
					auto thunk = (PIMAGE_THUNK_DATA)((UINT64)read.data() + rva_to_fva(nt, fthunk));
					while (thunk->u1.AddressOfData)
					{
						strcpy_s(imports[import_ptr].mod, module_name);
						imports[import_ptr].rva = fva_to_rva(nt, (uint64_t)&thunk->u1.Function - (uint64_t)read.data());
						if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
						{

							imports[import_ptr].type = packed_import_type::ordinal;
						}
						else
						{
							auto name = (PIMAGE_IMPORT_BY_NAME)(read.data() + rva_to_fva(nt, thunk->u1.AddressOfData));
							strcpy_s(imports[import_ptr].name, name->Name);
							imports[import_ptr].type = packed_import_type::name;
						}

						thunk += 1;
						import_ptr += 1;
					}
				}
			}
		}

		std::ofstream out("packed.dat", std::ios_base::binary);
		out.write((char*)allocator.img, allocator.cur_size);
		out.close();
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Correct usage: BinConPacker app.exe" << std::endl;
		goto _ret;
    }

    bc::pack(argv[1]);

_ret:
	std::cin.get();
	return 0;
}
