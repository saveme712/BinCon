#pragma once
#include "bc_common.h"
#include <intrin.h>
#include <Windows.h>

namespace bc
{
	typedef void (*fn_integrity_check_failed)(bc_error err);

	void install_anti_debug();
	void verify_anti_debug(fn_integrity_check_failed on_failure);
	bool verify_ret_addr(void* func, void* ret, HMODULE m);

	class bc_win_lock : public bc_lock
	{
	private:
		CRITICAL_SECTION section;

	public:
		bc_win_lock();

	public:
		virtual void enter();
		virtual void exit();
	};

#define VERIFY_RET_ADDR(F) verify_ret_addr((void*)F, _ReturnAddress(), NULL)
#define VERIFY_RET_ADDR_M(F,M) verify_ret_addr((void*)F, _ReturnAddress(), M)
}