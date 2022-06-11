#include <bc_windows.h>
#include <Windows.h>
#include <cstdint>

#include <xorstr.hpp>

/// <summary>
/// Installs a hook on DbgUiRemoteBreakin so that the process
/// will crash whenever a debugger is attached.
/// </summary>
void hook_DbgUiRemoteBreakin()
{
	DWORD old_protect;
	auto addr = GetProcAddress(GetModuleHandleA(xorstr_("ntdll.dll")), xorstr_("DbgUiRemoteBreakin"));
	if (addr)
	{
		VirtualProtect((LPVOID)addr, 15, PAGE_EXECUTE_READWRITE, &old_protect);
		for (size_t i = 0; i < 15; i++)
		{
			((int8_t*)addr)[i] = (int8_t)rand();
		}
		VirtualProtect((LPVOID)addr, 15, old_protect, &old_protect);
	}
}

void install_anti_debug()
{
	hook_DbgUiRemoteBreakin();
}