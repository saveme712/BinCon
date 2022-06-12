#pragma once
#include <Windows.h>
#include "bc_undocumented.h"

namespace bc
{
	class peb_walker
	{
	private:
		//
		// The pointer to the raw PEB.
		//
		PRE_PEB Peb;

	public:
		__forceinline peb_walker(PRE_PEB Peb)
		{
			this->Peb = Peb;
		}

	public:
		//
		// Iterates all PEB entries.
		//
		template<typename FN>
		void iterate(FN iterator)
		{
			PLIST_ENTRY list = &Peb->Ldr->InMemoryOrderModuleList;
			PLIST_ENTRY entry = list->Flink;
			while (entry != list && entry)
			{
				RE_LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(entry, RE_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
				iterator(mod, entry);

				entry = entry->Flink;
			}
		}

		//
		// Resolve a module.
		//
		void* resolve_module(const wchar_t* name);

		//
		// Resolves a function.
		//
		void* resolve_function(const wchar_t*, const char* function);

		//
		// Determines if an address is located within a module.
		//
		bool is_within_module(void* addr);

	public:
		static peb_walker query();
		static peb_walker tib();
	};

}