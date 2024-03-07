#pragma once
#include "bc_var.h"
#include "bc_log.h"

#include <map>

namespace bc
{
	typedef uint64_t dynamic_struct_key;

	struct dynamic_struct_pre_field
	{
		dynamic_struct_key key;
		size_t sz;
	};

	template<uint64_t ALIGNMENT>
	class dynamic_struct
	{
	private:
		void* data = NULL;
		size_t cur_sz = 0;

		obfuscated_prim64<dynamic_struct_key, 0x1337, __LINE__> alloc_key = 1;
		std::map<obfuscated_prim64<dynamic_struct_key, 0x1337, __LINE__>, obfuscated_prim64<uint64_t, 0x1337, __LINE__>> field_offsets;

	public:
		__forceinline dynamic_struct_key add_random_padding()
		{
			auto sz = rand() % 100;
			if (sz % ALIGNMENT)
			{
				sz += (ALIGNMENT - (sz % ALIGNMENT));
			}

			LOG("Sz: " << sz);
			auto key = add_field(sz);
			auto ref = ref_field<char>(key);
			for (auto i = 0; i < sz; i++)
			{
				ref[i] = (char)rand();
			}
			return key;
		}

		template<typename T>
		__forceinline dynamic_struct_key add_field_typed()
		{
			auto num_padding = (rand() % 10) + 3;
			for (auto i = 0; i < num_padding; i++)
			{
				add_random_padding();
			}

			auto sz = sizeof(T);

			data = realloc(data, cur_sz + sz);
			field_offsets[alloc_key.get()] = cur_sz;

			auto ti = (T*)((char*)data + cur_sz);
			*ti = T();

			if (sz % ALIGNMENT)
			{
				sz += (ALIGNMENT - (sz % ALIGNMENT));
			}

			cur_sz += sz;
			alloc_key += 1;
			return alloc_key - 1;
		}

		__forceinline dynamic_struct_key add_field(size_t sz)
		{
			if (!sz)
			{
				return 0;
			}

			data = realloc(data, cur_sz + sz);
			field_offsets[alloc_key.get()] = cur_sz;

			if (sz % ALIGNMENT)
			{
				sz += (ALIGNMENT - (sz % ALIGNMENT));
			}

			cur_sz += sz;
			alloc_key += 1;
			return alloc_key - 1;
		}

	public:
		template<typename T>
		__forceinline T* ref_field(dynamic_struct_key key)
		{
			if (!key)
			{
				return NULL;
			}

			return (T*)((char*)data + field_offsets[key]);
		}

		template<typename T>
		__forceinline T get_field(dynamic_struct_key key)
		{
			if (!key)
			{
				return T();
			}


			return *((T*)((char*)data + field_offsets[key]));
		}
	};
}