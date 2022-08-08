#pragma once
#include <bc_var.h>
#include <bc_integrity.h>
#include <bc_peb.h>
#include <bc_windows.h>
#include <bc_gen_struct.h>

#include <xorstr.hpp>

#include <Windows.h>

namespace bc
{
#pragma pack(push, 1)
	typedef void (*fn_verify_anti_debug)(fn_integrity_check_failed on_failure);
	typedef void (*fn_re_encrypt_code)();
	typedef void* (*fn_alloc_encrypted)(size_t amount);
	typedef void* (*fn_free_encrypted)(uint64_t ptr);

	enum class packed_app_option : uint8_t
	{
		chal_entry = (1 << 0),
		console = (1 << 1),
		anti_debug = (1 << 2),
		lazy_load_code = (1 << 3)
	};

	enum class packed_section_characteristic : uint64_t
	{
		can_lazy_load = (1 << 0)
	};

	__forceinline bool has_option(packed_app* app, packed_app_option option)
	{
		return (app->options.get() & (uint8_t)option) == (uint8_t)option;
	}

	struct chal_entry
	{
		obfuscated_prim64<uint64_t> run_tick;
		obfuscated_prim64<fn_verify_anti_debug> verify_anti_debug;
		obfuscated_prim64<fn_re_encrypt_code> re_encrypt_code;
		obfuscated_prim64<fn_alloc_encrypted> alloc_enc;
		obfuscated_prim64<fn_free_encrypted> free_enc;

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

	__forceinline chal_entry* get_chal_entry()
	{
		return (chal_entry*)GetProcAddress((HMODULE)0xBC, xorstr_("pack_interface"));
	}
#pragma pack(pop)
}