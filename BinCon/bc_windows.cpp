#include <bc_windows.h>
#include <bc_var.h>
#include <bc_integrity.h>
#include <bc_peb.h>

#include <Windows.h>
#include <cstdint>

#include <xorstr.hpp>

namespace bc
{
	static obfuscated_prim64<uint32_t> checksum_DbgUiRemoteBreakin;
	static obfuscated_prim64<void*> addr_DbgUiRemoteBreakin;
	static bool hang_system_in_progress = false;
	static HHOOK dummy_keyboard_hook;

	/// <summary>
	/// Installs a hook on DbgUiRemoteBreakin so that the process
	/// will crash whenever a debugger is attached.
	/// </summary>
	static void hook_DbgUiRemoteBreakin()
	{
		char rnd_gen[15];
		for (size_t i = 0; i < 15; i++)
		{
			rnd_gen[i] = (char)rand();
		}
		checksum_DbgUiRemoteBreakin = crc32(rnd_gen, 15);

		auto wrapper_VirtualProtect = peb_walker::func<decltype(VirtualProtect)*>(xorstr_(L"Kernel32.dll"), xorstr_("VirtualProtect"));

		DWORD old_protect;
		wrapper_VirtualProtect(addr_DbgUiRemoteBreakin.get(), 15, PAGE_EXECUTE_READWRITE, &old_protect);
		memcpy(addr_DbgUiRemoteBreakin.get(), rnd_gen, 15);
		wrapper_VirtualProtect(addr_DbgUiRemoteBreakin.get(), 15, old_protect, &old_protect);
	}

	/// <summary>
	/// A keyboard hook handler that does nothing.
	/// </summary>
	static LRESULT CALLBACK dummy_keyboard_handler(int nCode, WPARAM wParam, LPARAM lParam)
	{
		return CallNextHookEx(dummy_keyboard_hook, nCode, wParam, lParam);
	}

	/// <summary>
	/// Hooks the keyboards, and forwards input until a request to hang
	/// the system is made. This will also hang the system when a debugger is attached,
	/// as events will be blocked.
	/// </summary>
	static void hook_keyboard()
	{
		dummy_keyboard_hook = SetWindowsHookEx(WH_KEYBOARD_LL, dummy_keyboard_handler, NULL, 0);
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0) > 0 && !hang_system_in_progress)
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	void install_anti_debug()
	{
		auto walker = peb_walker::tib();
		addr_DbgUiRemoteBreakin = walker.resolve_function(xorstr_(L"ntdll.dll"), xorstr_("DbgUiRemoteBreakin"));
		hook_DbgUiRemoteBreakin();
		
		// must run this in another thread
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hook_keyboard, NULL, 0, NULL);
	}

	void verify_anti_debug(fn_integrity_check_failed on_failure)
	{
		if (crc32(addr_DbgUiRemoteBreakin.get(), 15) != checksum_DbgUiRemoteBreakin.get())
		{
			on_failure(bc_error::bad_hook_checksum);
		}
	}

	void hang_system()
	{
		hang_system_in_progress = true;
	}

	RE_PEB* get_peb()
	{
		return (RE_PEB*)__readgsqword(offsetof(GS, Peb));
	}
}