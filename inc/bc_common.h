#pragma once

namespace bc
{
	#define NOINLINE __declspec(noinline)
	#define INLINE __forceinline

	enum class bc_error
	{
		success,
		not_enough_memory,
		bad_hook_checksum,
		debugger_attached,
		bad_module_checksum,
		reencrypt_thread_not_running,
	};

	class bc_lock
	{
	public:
		virtual void enter() = 0;
		virtual void exit() = 0;
	};
}