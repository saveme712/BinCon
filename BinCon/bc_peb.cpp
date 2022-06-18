#include <bc_peb.h>
#include <bc_util.h>

#include <cstdint>

#include <xorstr.hpp>

namespace bc
{

	PVOID peb_walker::resolve_module(const wchar_t* name)
	{
		wchar_t tmp_name[64];
		wcscpy_s(tmp_name, name);
		_wcslwr_s(tmp_name);

		void* found = nullptr;

		iterate([&tmp_name, &found](RE_LDR_DATA_TABLE_ENTRY* mod, PLIST_ENTRY list_entry)
		{
			wchar_t tmp_dll[64];
			wcscpy_s(tmp_dll, mod->BaseDllName.Buffer);
			_wcslwr_s(tmp_dll);

			if (!wcscmp(tmp_dll, tmp_name))
			{
				found = mod->DllBase;
			}
		});

		return found;
	}

	void* peb_walker::resolve_function(const wchar_t* module, const char* function)
	{
		auto mod = (char*)resolve_module(module);
		if (!mod)
		{
			return nullptr;
		}

		char tmp_func[256];
		strcpy_s(tmp_func, function);
		_strlwr_s(tmp_func);

		char tmp_name[256];
		char export_module[64];
		char export_function[256];
		wchar_t export_module_wide[64];

		auto dos_header = (PIMAGE_DOS_HEADER)mod;
		auto nt_headers = (PIMAGE_NT_HEADERS)(mod + dos_header->e_lfanew);

		auto file_header = &nt_headers->FileHeader;
		auto opt_header = &nt_headers->OptionalHeader;

		auto export_dir = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!export_dir.VirtualAddress || !export_dir.Size)
		{
			return nullptr;
		}

		if (export_dir.VirtualAddress)
		{
			auto expr = (IMAGE_EXPORT_DIRECTORY*)(mod + export_dir.VirtualAddress);
			if (!expr->AddressOfNames || !expr->AddressOfNameOrdinals || !expr->AddressOfFunctions)
			{
				return nullptr;
			}

			auto names = (INT32*)(mod + expr->AddressOfNames);
			auto ods = (USHORT*)(mod + expr->AddressOfNameOrdinals);
			auto funcs = (INT32*)(mod + expr->AddressOfFunctions);

			for (auto i = 0; i < expr->NumberOfNames; i++)
			{
				auto name_off = names[i];
				strcpy_s(tmp_name, (PCSTR)mod + name_off);
				_strlwr_s(tmp_name);

				if (!strcmp(tmp_func, tmp_name))
				{
					auto func = mod + funcs[ods[i]];
					auto forwarded = (func >= (PCHAR)expr && func < ((PCHAR)expr + export_dir.Size));

					if (forwarded)
					{
						char whole[64];
						strcpy_s(whole, sizeof(whole), (PCHAR)func);

						auto period = -1;
						for (INT32 i = 0; i < strlen(whole); i++)
						{
							if (whole[i] == '.')
							{
								period = i;
								break;
							}
						}

						memset(export_module, 0, 64);
						memcpy(export_module, whole, period);

						memset(export_function, 0, 64);
						memcpy(export_function, whole + period + 1, strlen(whole) - period);

						strcat_s(export_module, xorstr_(".dll"));

						ascii_to_wide(export_module, export_module_wide);
						_wcslwr_s(export_module_wide);

						func = (char*)resolve_function(export_module_wide, export_function);
					}

					return func;
				}
			}
		}

		return nullptr;
	}

	bool peb_walker::is_within_module(void* addr)
	{
		bool within = false;

		iterate([&addr, &within](RE_LDR_DATA_TABLE_ENTRY* mod, PLIST_ENTRY list_entry)
		{
			if (addr >= mod->DllBase && 
				addr < (void*)((uint64_t)mod->DllBase + mod->SizeOfImage))
			{
				within = true;
			}
		});

		return within;
	}

	peb_walker peb_walker::query()
	{
		static FnNtQueryInformationProcess NtQueryInformationProcess = NULL;
		if (!NtQueryInformationProcess)
		{
			NtQueryInformationProcess = (FnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA(xorstr_("ntdll.dll")), xorstr_("NtQueryInformationProcess"));
		}

		RE_PROCESS_BASIC_INFORMATION info;
		NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0, &info, sizeof(info), 0);

		return peb_walker((PRE_PEB)info.PebBaseAddress);
	}

	peb_walker peb_walker::tib()
	{
		return peb_walker((PRE_PEB)get_peb());
	}
}