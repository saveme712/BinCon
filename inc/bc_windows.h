#pragma once
#include "bc_common.h"

namespace bc
{
	typedef void (*fn_integrity_check_failed)(bc_error err);

	void install_anti_debug();
	void verify_anti_debug(fn_integrity_check_failed on_failure);

	void hang_system();
}