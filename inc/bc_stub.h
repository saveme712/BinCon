#pragma once
#include <bc_var.h>
#include <bc_integrity.h>
#include <bc_peb.h>
#include <bc_windows.h>
#include <bc_gen_struct.h>

#include <xorstr.hpp>

namespace bc
{
#pragma pack(push, 1)
	typedef void (*fn_verify_anti_debug)(fn_integrity_check_failed on_failure);

	enum class packed_app_option : uint8_t
	{
		chal_entry = (1 << 0),
		console = (1 << 1),
		anti_debug = (1 << 2)
	};


	__forceinline bool has_option(packed_app* app, packed_app_option option)
	{
		return (app->options.get() & (uint8_t)option) == (uint8_t)option;
	}

	struct chal_entry
	{
		obfuscated_prim64<uint64_t> run_tick;
		obfuscated_prim64<fn_verify_anti_debug> verify_anti_debug;
		union
		{
			obfuscated_prim64<uint32_t> crc;
			bool crc_anchor;
		};

		chal_entry() { }
	};

	__forceinline chal_entry gen_chal_entry()
	{
		chal_entry entry;
		entry.run_tick = peb_walker::func<decltype(GetTickCount64)*>(xorstr_(L"Kernel32.dll"), xorstr_("GetTickCount64"))();
		entry.crc = crc32(&entry, offsetof(chal_entry, crc_anchor));
		return entry;
	}

	__forceinline bool verify_chal_entry(chal_entry* ce)
	{
		bool r = false;
		uint64_t delta;

		if (crc32(ce, offsetof(chal_entry, crc_anchor)) != ce->crc)
		{
			goto _ret;
		}
		
		delta = peb_walker::func<decltype(GetTickCount64)*>(xorstr_(L"Kernel32.dll"), xorstr_("GetTickCount64"))() - ce->run_tick;
		if (delta > 10000)
		{
			goto _ret;
		}

		r = true;

	_ret:
		return r;
	}
#pragma pack(pop)
}