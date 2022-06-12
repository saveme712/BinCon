#pragma once
#include <cstdint>

namespace bc
{
	extern uint32_t crc32_table[256];

	void init_crc32_table();

	__forceinline uint32_t update_crc32(uint32_t initial, const void* buf, size_t len)
	{
		auto c = initial ^ 0xFFFFFFFF;
		auto u = (const uint8_t*)buf;
		for (size_t i = 0; i < len; ++i)
		{
			c = crc32_table[(c ^ u[i]) & 0xFF] ^ (c >> 8);
		}
		return c ^ 0xFFFFFFFF;
	}

	__forceinline uint32_t crc32(const void* buf, size_t len)
	{
		return update_crc32(0, buf, len);
	}
}