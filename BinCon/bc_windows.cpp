#include <bc_windows.h>
#include <bc_var.h>
#include <bc_integrity.h>
#include <bc_peb.h>
#include <bc_thirdparty.h>
#include <bc_log.h>
#include <bc_iat.h>

#include <cstdint>

#include <xorstr.hpp>

#define DR_MAGIC 0xffff000000000000

namespace bc
{
	static obfuscated_prim64<uint32_t, 0x1337, __LINE__> checksum_DbgUiRemoteBreakin;
	static obfuscated_prim64<void*, 0x1337, __LINE__> addr_DbgUiRemoteBreakin;
	static bool hang_system_in_progress = false;
	static HHOOK dummy_keyboard_hook;
	static uint64_t expected_debug_regs[4];

	/// <summary>
	/// Installs a hook on DbgUiRemoteBreakin so that the process
	/// will crash whenever a debugger is attached.
	/// </summary>
	static INLINE void hook_DbgUiRemoteBreakin()
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
	static NOINLINE void hook_keyboard()
	{
		VM({
			dummy_keyboard_hook = SetWindowsHookEx(WH_KEYBOARD_LL, dummy_keyboard_handler, NULL, 0);
			MSG msg;
			while (GetMessage(&msg, NULL, 0, 0) > 0 && !hang_system_in_progress)
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		});
	}

	/// <summary>
	/// Verifies that debug registers have our dummy values in them.
	/// </summary>
	static INLINE bool verify_debug_regs()
	{
		auto ret = false;
		auto thr = IAT.GetCurrentThread();

		CONTEXT thr_ctx;
		thr_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (!IAT.GetThreadContext(thr, &thr_ctx))
		{
			goto _ret;
		}

		if (thr_ctx.Dr0 == DR_MAGIC &&
			thr_ctx.Dr1 == DR_MAGIC &&
			thr_ctx.Dr2 == DR_MAGIC &&
			thr_ctx.Dr3 == DR_MAGIC)
		{
			ret = true;
		}

	_ret:
		return ret;
	}
	/// <summary>
	/// Sets dummy values to all debug address registers.
	/// </summary>
	static INLINE bool randomize_debug_regs()
	{
		auto ret = false;
		auto thr = IAT.GetCurrentThread();

		CONTEXT thr_ctx; 
		thr_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (!IAT.GetThreadContext(thr, &thr_ctx))
		{
			goto _ret;
		}

		thr_ctx.Dr0 = DR_MAGIC;
		thr_ctx.Dr1 = DR_MAGIC;
		thr_ctx.Dr2 = DR_MAGIC;
		thr_ctx.Dr3 = DR_MAGIC;

		if (!IAT.SetThreadContext(thr, &thr_ctx))
		{
			goto _ret;
		}
		
		ret = true;

	_ret:
		return ret;
	}

	NOINLINE void install_anti_debug()
	{
		VM({
			auto walker = peb_walker::tib();
			addr_DbgUiRemoteBreakin = walker.resolve_function(xorstr_(L"ntdll.dll"), xorstr_("DbgUiRemoteBreakin"));
			hook_DbgUiRemoteBreakin();
			randomize_debug_regs();
			IAT.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hook_keyboard, NULL, 0, NULL);
		});
	}

	void verify_anti_debug(fn_integrity_check_failed on_failure)
	{
		VM({
			LOG("Checking IsDebuggerPresent");
			if (IAT.IsDebuggerPresent())
			{
				on_failure(bc_error::debugger_attached);
			}

			LOG("Checking BeingDebugged");
			if (get_peb()->BeingDebugged)
			{
				on_failure(bc_error::debugger_attached);
			}

			LOG("Checking NtGlobalFlag");
			if (get_peb()->NtGlobalFlag)
			{
				on_failure(bc_error::debugger_attached);
			}
			
			LOG("Verifying debug registers");
			if (!verify_debug_regs())
			{
				on_failure(bc_error::debugger_attached);
			}

			LOG("Verifying DbgUiRemoteBreakin hook");
			if (crc32(addr_DbgUiRemoteBreakin.get(), 15) != checksum_DbgUiRemoteBreakin.get())
			{
				on_failure(bc_error::bad_hook_checksum);
			}
		});
	}

	void hang_system()
	{
		hang_system_in_progress = true;
	}

	/// <summary>
	/// Verifies that the provided return address contains a valid call within the provided module beforehand.
	/// 
	/// If the module is NULL, then it must just have a valid call.
	/// </summary>
	static INLINE bool verify_ret_addr_ins(void* func, void* ret, HMODULE mod)
	{
		HMODULE ret_mod = NULL;
		if (mod)
		{
			ret_mod = peb_walker::tib().get_hmodule(ret);
		}

		uint8_t ret_bytes[15];
		memcpy(ret_bytes, (char*)ret - 5, sizeof(ret_bytes));
		if (ret_bytes[0] == 0xe8)
		{
			auto real_call_addr = (void*)((uint64_t)ret + *((int32_t*)(ret_bytes + 1)));
			if (real_call_addr == func)
			{
				return (mod == NULL || mod == ret_mod);
			}
		}
		else if (ret_bytes[5] == 0x68 && ret_bytes[5 + 5] == 0xe8)
		{
			// vmp PUSH bytecode, CALL
			return (mod == NULL || mod == ret_mod);
		}

		// TODO FIXME add support for call reg, etc.
		return false;
	}

	/// <summary>
	/// Verifies that the return address is a valid call within the provided module.
	/// 
	/// If the module is NULL, then it must just be a valid call.
	/// </summary>
	bool verify_ret_addr(void* func, void* ret, HMODULE m)
	{
		auto bret = (uint64_t)ret;
		auto walker = peb_walker::tib();
		auto valid = false;
		walker.iterate([func, ret, m, bret, &valid](RE_LDR_DATA_TABLE_ENTRY* mod, PLIST_ENTRY list_entry)
		{
			auto base = (uint64_t)mod->DllBase;
			auto dos_header = (PIMAGE_DOS_HEADER)base;
			auto nt_headers = (PIMAGE_NT_HEADERS)(base + dos_header->e_lfanew);
			auto end = (base + nt_headers->OptionalHeader.SizeOfImage);
			if (bret >= base && bret < (base + end))
			{
				valid = verify_ret_addr_ins(func, ret, m);
			}
		});
		return valid;
	}

	RE_PEB* get_peb()
	{
		return (RE_PEB*)__readgsqword(offsetof(GS, Peb));
	}

	bc_win_lock::bc_win_lock()
	{
		InitializeCriticalSection(&section);
	}

	void bc_win_lock::enter()
	{
		EnterCriticalSection(&section);
	}

	void bc_win_lock::exit()
	{
		LeaveCriticalSection(&section);
	}
}