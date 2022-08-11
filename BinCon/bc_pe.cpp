#include <bc_pe.h>
#include <bc_integrity.h>
#include <bc_log.h>

#include <Psapi.h>

#include <fstream>
#include <vector>

namespace bc
{
	bool pe_validator::validate(void* original)
	{
		auto dos_header = (PIMAGE_DOS_HEADER)original;
		auto nt_headers = (PIMAGE_NT_HEADERS)((char*)original + dos_header->e_lfanew);

		auto section = IMAGE_FIRST_SECTION(nt_headers);
		auto valid = true;
		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
		{
			if (section->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
			{
				auto crc = crc32(section->Name, sizeof(section->Name));
				auto s_crc = crc32((char*)original + section->VirtualAddress, section->SizeOfRawData);
				if (section_checksums.find(crc) == section_checksums.end())
				{
					LOG("Missing section -> " << section->Name);
					valid = false;
				}
				else if (section_checksums[crc] != s_crc)
				{
					LOG("Bad CS -> " << section->Name << ", " << crc << ", " << s_crc << ", " << section_checksums[crc]);
					valid = false;
				}
				else
				{
					LOG("Valid CS -> " << section->Name << ", " << crc << ", " << s_crc << ", " << section_checksums[crc])
				}
			}
		}
		return valid;
	}

	pe_validator pe_validator::map(void* original, void* data)
	{
		pe_validator v;
		v.section_checksums[0] = 0;

		auto dos_header = (PIMAGE_DOS_HEADER)data;
		auto nt_headers = (PIMAGE_NT_HEADERS)((char*)data + dos_header->e_lfanew);

		auto img_size = nt_headers->OptionalHeader.SizeOfImage;
		auto img_base = (char*)VirtualAlloc(NULL, img_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		memcpy(img_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		auto section = IMAGE_FIRST_SECTION(nt_headers);
		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
		{
			memcpy(img_base + section->VirtualAddress, (char*)data + section->PointerToRawData, section->SizeOfRawData);
		}

		auto& reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (auto rva = reloc_dir.VirtualAddress)
		{
			auto reloc_addr = img_base + rva;
			auto delta = (UINT64)original - (UINT64)nt_headers->OptionalHeader.ImageBase;
			for (auto cur = 0UL; cur < reloc_dir.Size; )
			{
				IMAGE_BASE_RELOCATION reloc;
				memcpy(&reloc, reloc_addr, sizeof(reloc));

				auto reloc_count = (reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto reloc_data = reloc_addr + sizeof(IMAGE_BASE_RELOCATION);
				auto reloc_base = img_base + reloc.VirtualAddress;

				for (auto i = 0UL; i < reloc_count; ++i, reloc_data += 2)
				{
					UINT16 data;
					memcpy(&data, reloc_data, sizeof(data));

					auto type = data >> 12;
					auto off = data & 0xFFF;

					if (type == IMAGE_REL_BASED_DIR64)
					{
						auto reloc_ptrd = reloc_base + off;
						UINT64 reloc_raw;

						memcpy(&reloc_raw, reloc_ptrd, sizeof(reloc_raw));
						reloc_raw += delta;
						memcpy(reloc_ptrd, &reloc_raw, sizeof(reloc_raw));
					}
				}

				cur += reloc.SizeOfBlock;
				reloc_addr = reloc_data;
			}
		}

		auto& import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (auto rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		{
			auto import_desc_addr = img_base + rva;

			IMAGE_IMPORT_DESCRIPTOR import_desc;
			memcpy(&import_desc, import_desc_addr, sizeof(import_desc));

			while (import_desc.FirstThunk)
			{
				auto mod_name_addr = img_base + import_desc.Name;
				CHAR mod_name[MAX_PATH];

				memcpy(mod_name, mod_name_addr, sizeof(mod_name));
				auto mod = LoadLibraryA(mod_name);

				auto thunk_addr = img_base + import_desc.FirstThunk;
				IMAGE_THUNK_DATA thunk;
				memcpy(&thunk, thunk_addr, sizeof(thunk));

				while (thunk.u1.AddressOfData)
				{
					if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG)
					{
						thunk.u1.Function = (ULONGLONG)GetProcAddress(mod, (LPCSTR)(thunk.u1.Ordinal & 0xffff));
					}
					else
					{
						auto ibn_addr = img_base + thunk.u1.AddressOfData;
						char ibn_full[sizeof(IMAGE_IMPORT_BY_NAME) + MAX_PATH];
						auto ibn = (PIMAGE_IMPORT_BY_NAME)ibn_full;
						memcpy(ibn, ibn_addr, sizeof(ibn_full));

						thunk.u1.Function = (ULONGLONG)GetProcAddress(mod, ibn->Name);
					}

					memcpy(thunk_addr, &thunk, sizeof(thunk));
					thunk_addr += sizeof(thunk);
					memcpy(&thunk, thunk_addr, sizeof(thunk));
				}

				import_desc_addr += sizeof(import_desc);
				memcpy(&import_desc, import_desc_addr, sizeof(import_desc));
			}
		}

		section = IMAGE_FIRST_SECTION(nt_headers);
		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
		{
			if (section->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
			{
				v.section_checksums[crc32(section->Name, sizeof(section->Name))] = crc32(img_base + section->VirtualAddress, section->SizeOfRawData);
			}
		}

		VirtualFree(img_base, img_size, MEM_FREE);
		return v;
	}


	pe_validator pe_validator::map(HMODULE mod)
	{
		char name[MAX_PATH];
		GetModuleFileNameExA(GetCurrentProcess(), mod, name, sizeof(name));

		auto file = CreateFileA(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		auto size = GetFileSize(file, NULL);
		DWORD bytes_read = 0;
		char* buffer = (char*)malloc(size + 1);
		ReadFile(file, buffer, size, &bytes_read, NULL);

		auto mapped = map((void*)mod, buffer);
		free(buffer);
		return mapped;
	}
}