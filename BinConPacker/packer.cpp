#include <iostream>
#include <vector>
#include <istream>
#include <fstream>
#include <Windows.h>
#include <iostream>

#include <bc_stub.h>
#include <bc_log.h>

namespace bc
{
	struct pre_packed_resource
	{
		uint16_t id;
		uint64_t off;
		uint64_t size;
	};

	class byte_allocator
	{
	public:
		void* img = nullptr;
		size_t cur_size = 0;
		size_t max_size = 0;

	public:
		byte_allocator(size_t size)
		{
			img = malloc(size);
			memset(img, 0, size);
			max_size = size;
		}

	public:
		template <typename T>
		T* append(size_t amount)
		{
			auto ret = (char*)img + cur_size;
			if ((ret + amount) > ((char*)img + max_size))
			{
				ERR("Out of bounds! " << cur_size << ":" << max_size << ":" << amount);
			}

			cur_size += amount;
			return (T*)ret;
		}

		uint64_t off(void* v)
		{
			return (uint64_t)v - (uint64_t)img;
		}
	};

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

		ERR("failed to resolve rva to fva " << std::hex << rva << std::endl);
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

		ERR("failed to resolve fva to rva " << std::hex << fva << std::endl);
		return 0;
	}

	uint64_t packed_rva_to_fva(packed_app* app, uint64_t rva)
	{
		auto sections = (packed_section*)((char*)app + app->off_to_sections.off.get());
		for (auto i = 0; i < app->off_to_sections.num_elements.get(); i++)
		{
			auto section = &sections[i];
			if (rva >= section->rva && rva < (section->rva + section->size_of_data))
			{
				return rva - section->rva + section->off_to_data;
			}
		}
		return 0;
	}

	template<typename FN>
	static __forceinline void parse_rsc_entries(SIZE_T num_tabs, std::vector<uint16_t>& name_stack, PIMAGE_RESOURCE_DIRECTORY directory, PIMAGE_RESOURCE_DIRECTORY_ENTRY entry, FN iterator)
	{
		name_stack.push_back(entry->Name);
		if (entry->OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
		{
			auto new_dir = (PIMAGE_RESOURCE_DIRECTORY)((char*)directory + (entry->OffsetToDirectory));
			auto num_entries = new_dir->NumberOfIdEntries + new_dir->NumberOfNamedEntries;

			if (num_entries)
			{
				auto child = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((char*)new_dir + sizeof(IMAGE_RESOURCE_DIRECTORY));
				for (auto i = 0; i < num_entries; i++)
				{
					parse_rsc_entries(num_tabs + 1, name_stack, directory, &child[i], iterator);
				}
			}
		}
		else
		{
			auto e = (PIMAGE_RESOURCE_DATA_ENTRY)((char*)directory + (entry->OffsetToData));

			iterator(name_stack, e);
		}
		name_stack.erase(name_stack.end() - 1);
	}

	void fill_rng(void* p, size_t sz)
	{
		for (size_t i = 0; i < sz; i++)
		{
			((char*)p)[i] = (char)rand();
		}
	}

	void erase_data_directory(PIMAGE_NT_HEADERS nt, PIMAGE_DATA_DIRECTORY data_directory, packed_app* app)
	{
		if (auto fva = packed_rva_to_fva(app, data_directory->VirtualAddress))
		{
			auto end_fva = fva + data_directory->Size;
			if (fva >= 0 && end_fva < (app->size_of_app.get()))
			{
				fill_rng((char*)app + fva, data_directory->Size);
			}
		}
	}

    void pack(char* input, bool cfg_command_line, bool cfg_lazy_load_code)
    {
        auto read = read_file(input);
        auto dos = (PIMAGE_DOS_HEADER)(read.data());
        auto nt = (PIMAGE_NT_HEADERS)(read.data() + dos->e_lfanew);

		INFO("calculating image size" << std::endl);

		auto reloc_count = 0;
		auto sect_size = 0;
		auto import_count = 0;
		auto tls_callback_count = 0;
		auto rsc_size = 0;
		std::vector<pre_packed_resource> resource_data_entries;
		if (auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		{
			auto base_reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			auto reloc = (PIMAGE_BASE_RELOCATION)((UINT64)read.data() + rva_to_fva(nt, rva));
			auto reloc_ptr = 0;

			for (auto cs = 0UL; cs < base_reloc_dir.Size;)
			{
				auto c_reloc_count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto reloc_data = (PUINT16)((PCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION));

				for (auto i = 0UL; i < c_reloc_count; ++i, ++reloc_data)
				{
					auto data = *reloc_data;
					auto type = data >> 12;
					auto offset = data & 0xFFF;

					if (type == IMAGE_REL_BASED_DIR64)
					{
						reloc_count += 1;
					}
				}

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
		
		if (auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
		{
			auto tls_dir = (PIMAGE_TLS_DIRECTORY)((UINT64)read.data() + rva_to_fva(nt, rva));
			if (tls_dir->AddressOfCallBacks)
			{
				auto cur = (UINT64*)((UINT64)read.data() + rva_to_fva(nt, tls_dir->AddressOfCallBacks - nt->OptionalHeader.ImageBase));
				while (*cur)
				{
					tls_callback_count += 1;
					cur += 1;
				}
			}
		}

		if (auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
		{
			auto rsc_dir = (PIMAGE_RESOURCE_DIRECTORY)((UINT64)read.data() + rva_to_fva(nt, rva));
			auto num_entries = rsc_dir->NumberOfIdEntries + rsc_dir->NumberOfNamedEntries;
			if (num_entries)
			{
				auto dir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((char*)rsc_dir + sizeof(IMAGE_RESOURCE_DIRECTORY));
				for (auto i = 0; i < (rsc_dir->NumberOfIdEntries + rsc_dir->NumberOfNamedEntries); i++)
				{
					std::vector<uint16_t> name_stack;
					parse_rsc_entries(1, name_stack, rsc_dir, &dir[i], [nt, &resource_data_entries, &rsc_size](auto& name_stack, auto entry)
					{
						if (name_stack.size() == 3)
						{
							rsc_size += entry->Size;

							pre_packed_resource rsc;
							rsc.id = name_stack[1];
							rsc.off = rva_to_fva(nt, entry->OffsetToData);
							rsc.size = entry->Size;
							resource_data_entries.push_back(rsc);
						}
					});
				}
			}
		}

        auto size_of_img =
            sizeof(packed_app) +
			nt->OptionalHeader.SizeOfHeaders +
            (nt->FileHeader.NumberOfSections * sizeof(packed_section)) +
			(resource_data_entries.size() * sizeof(packed_resource)) +
			(reloc_count * sizeof(packed_reloc)) +
			(import_count * sizeof(packed_import)) +
			(tls_callback_count * sizeof(packed_tls_callback)) +
			rsc_size +
			sect_size;

		INFO(" -> image_data" << std::endl);
		INFO("  -> section_count= " << nt->FileHeader.NumberOfSections);
		INFO("  -> resource_count= " << resource_data_entries.size());
		INFO("  -> reloc_count= " << reloc_count << ":" << rsc_size);
		INFO("  -> import_count= " << import_count);
		INFO("  -> tls_cb_count= " << tls_callback_count);
		INFO("  -> size_of_img= " << size_of_img);

		byte_allocator allocator(size_of_img);
		auto app = allocator.append<packed_app>(sizeof(packed_app));
		INFO(" -> app sz:" << allocator.cur_size << ":" << allocator.max_size);

		auto headers = allocator.append<char>(nt->OptionalHeader.SizeOfHeaders);
		INFO(" -> headers sz:" << allocator.cur_size << ":" << allocator.max_size);

		auto sections = allocator.append<packed_section>(nt->FileHeader.NumberOfSections * sizeof(packed_section));
		INFO(" -> sections sz:" << allocator.cur_size << ":" << allocator.max_size);

		auto resources = allocator.append<packed_resource>(resource_data_entries.size() * sizeof(packed_resource));
		INFO(" -> resources sz:" << allocator.cur_size << ":" << allocator.max_size);

		auto imports = allocator.append<packed_import>(import_count * sizeof(packed_import));
		INFO(" -> import sz:" << allocator.cur_size << ":" << allocator.max_size);

		auto relocs = allocator.append<packed_reloc>(reloc_count * sizeof(packed_reloc));
		INFO(" -> reloc sz:" << allocator.cur_size << ":" << allocator.max_size);

		auto tls_callbacks = allocator.append<packed_reloc>(tls_callback_count * sizeof(packed_tls_callback));
		INFO(" -> tls cb sz:" << allocator.cur_size << ":" << allocator.max_size);

		if (cfg_command_line)
		{
			app->options |= (uint8_t)packed_app_option::console;
		}

		if (cfg_lazy_load_code)
		{
			app->options |= (uint8_t)packed_app_option::lazy_load_code;
		}

		app->ep = nt->OptionalHeader.AddressOfEntryPoint;
		app->size_of_img = nt->OptionalHeader.SizeOfImage;
		app->size_of_app = size_of_img;
		app->preferred_base = nt->OptionalHeader.ImageBase;

		app->off_to_headers.num_elements = nt->OptionalHeader.SizeOfHeaders;
		app->off_to_headers.off = allocator.off(headers);

		app->off_to_sections.num_elements = nt->FileHeader.NumberOfSections;
		app->off_to_sections.off = allocator.off(sections);

		app->off_to_resources.num_elements = resource_data_entries.size();
		app->off_to_resources.off = allocator.off(resources);

		app->off_to_relocs.num_elements = reloc_count;
		app->off_to_relocs.off = allocator.off(relocs);

		app->off_to_iat.num_elements = import_count;
		app->off_to_iat.off = allocator.off(imports);

		INFO(" -> building headers");
		memcpy(headers, dos, nt->OptionalHeader.SizeOfHeaders);

		INFO(" -> building sections:" << allocator.cur_size << ":" << allocator.max_size);
		sect = IMAGE_FIRST_SECTION(nt);
		for (auto i = 0; i < nt->FileHeader.NumberOfSections; i++, sect++)
		{
			sections[i].size_of_data = sect->SizeOfRawData;
			sections[i].rva = sect->VirtualAddress;

			auto section = allocator.append<void>(sect->SizeOfRawData);
			memcpy(section, read.data() + sect->PointerToRawData, sect->SizeOfRawData);

			obfuscated_byte_array<0x1337, 7> ba(section, sect->SizeOfRawData);
			ba.encrypt();

			sections[i].off_to_data = allocator.off(section);
			sections[i].characteristics = 0;

			if (sect->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
			{
				sections[i].characteristics |= (uint64_t)packed_section_characteristic::can_lazy_load;
			}
		}

		INFO(" -> building resources");
		for (auto i = 0; i < resource_data_entries.size(); i++)
		{
			auto rsc_packed = &resources[i];

			auto rsc_entry = resource_data_entries[i];
			auto rsc_data = allocator.append<void>(rsc_entry.size);

			memcpy(rsc_data, read.data() + rsc_entry.off, rsc_entry.size);

			rsc_packed->id = rsc_entry.id;
			rsc_packed->off_to_data = allocator.off(rsc_data);
			rsc_packed->size_of_data = rsc_entry.size;
		}

		INFO(" -> building relocations");
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

					if (type == IMAGE_REL_BASED_DIR64)
					{
						relocs[reloc_ptr].rva = reloc->VirtualAddress + offset;
						reloc_ptr += 1;
					}
				}

				cs += reloc->SizeOfBlock;
				reloc = (PIMAGE_BASE_RELOCATION)reloc_data;
			}
		}

		INFO("building imports");
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
						imports[import_ptr].mod = module_name;
						imports[import_ptr].rva = fva_to_rva(nt, (uint64_t)&thunk->u1.Function - (uint64_t)read.data());
						if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
						{
							imports[import_ptr].ordinal = thunk->u1.Ordinal & 0xffff;
							imports[import_ptr].type = packed_import_type::ordinal;
						}
						else
						{
							auto name = (PIMAGE_IMPORT_BY_NAME)(read.data() + rva_to_fva(nt, thunk->u1.AddressOfData));
							imports[import_ptr].name = name->Name;
							imports[import_ptr].type = packed_import_type::name;
						}

						thunk += 1;
						import_ptr += 1;
					}
				}
			}
		}

		INFO("building TLS");
		if (auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
		{
			auto tls_ptr = 0;
			auto tls_dir = (PIMAGE_TLS_DIRECTORY)((UINT64)read.data() + rva_to_fva(nt, rva));
			if (tls_dir->AddressOfCallBacks)
			{
				auto cur = (UINT64*)((UINT64)read.data() + rva_to_fva(nt, tls_dir->AddressOfCallBacks - nt->OptionalHeader.ImageBase));
				while (*cur)
				{
					tls_callbacks[tls_ptr].rva = (*cur - nt->OptionalHeader.ImageBase);
					tls_ptr += 1;
					cur += 1;
				}
			}
		}

		INFO("Allocator: " << size_of_img << ":" << allocator.cur_size);

		INFO("Erasing data directories from sections");
		erase_data_directory(nt, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS], app);
		erase_data_directory(nt, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC], app);
		erase_data_directory(nt, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG], app);
		erase_data_directory(nt, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY], app);
		erase_data_directory(nt, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT], app);
		erase_data_directory(nt, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG], app);

		INFO("Beginning resource update");
		auto rsc = BeginUpdateResource(L"BinConPackerStub.exe", TRUE);

		INFO("Updating resource " << rsc);
		if (UpdateResource(rsc, RT_RCDATA, L"p", MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (char*)allocator.img, allocator.cur_size))
		{
			EndUpdateResource(rsc, FALSE);
		}

		INFO("Done!");
    }
}

int main(int argc, char* argv[])
{
	
	bool cfg_command_line = false;
	bool cfg_lazy_load_code = false;

	srand(time(NULL));

    if (argc < 2)
    {
		ERR("Correct usage: BinConPacker app.exe [-command_line] [-lazy_load_code]");
		goto _ret;
    }

	for (auto i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "-command_line"))
		{
			cfg_command_line = true;
		}
		else if (!strcmp(argv[i], "-lazy_load_code"))
		{
			cfg_lazy_load_code = true;
		}
	}

	bc::pack(argv[1], cfg_command_line, cfg_lazy_load_code);

_ret:
	std::cin.get();
	return 0;
}
