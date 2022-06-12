#include <bc_integrity.h>

#define POLYNOMIAL_INIT 0xEDB88320

namespace bc
{
	uint32_t crc32_table[256];

	void init_crc32_table()
	{
		for (auto i = 0u; i < 256; i++)
		{
			auto c = i;
			for (auto j = 0; j < 8; j++)
			{
				if (c & 1)
				{
					c = POLYNOMIAL_INIT ^ (c >> 1);
				}
				else
				{
					c >>= 1;
				}
			}
			crc32_table[i] = c;
		}
	}
}