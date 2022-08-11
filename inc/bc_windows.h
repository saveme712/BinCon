#pragma once
#include "bc_common.h"
#include <intrin.h>

namespace bc
{
	typedef void (*fn_integrity_check_failed)(bc_error err);

	void install_anti_debug();
	void verify_anti_debug(fn_integrity_check_failed on_failure);

	void hang_system();
	bool verify_ret_addr(void* func, void* ret);

#define VERIFY_RET_ADDR(F) verify_ret_addr((void*)F, _ReturnAddress())
}