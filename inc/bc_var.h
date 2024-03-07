#pragma once
#include <cstdint>
#include <intrin.h>
#include <string>
#include "bc_gen.h"

namespace bc
{
	template <unsigned long long F, unsigned long long FL>
	class obfuscated_byte_array
	{
	private:
		char* data;
		size_t data_len;

	public:
		__forceinline obfuscated_byte_array(void* data, size_t data_len)
		{
			this->data = (char*)data;
			this->data_len = data_len;
		}

	public:
		__forceinline void encrypt()
		{
			uint64_t t1;
			uint64_t t2;

			for (auto i = 0; i < data_len / sizeof(uint64_t); i++)
			{
				t1 = *((uint64_t*)(data + (i * sizeof(uint64_t))));
				ENCRYPT(t2, t1, F, FL);

				*((uint64_t*)(data + (i * sizeof(uint64_t)))) = t2;
			}
		}

		__forceinline void decrypt()
		{
			uint64_t t1;
			uint64_t t2;

			for (auto i = 0; i < data_len / sizeof(uint64_t); i++)
			{
				t1 = *((uint64_t*)(data + (i * sizeof(uint64_t))));
				DECRYPT(t2, t1, F, FL);

				*((uint64_t*)(data + (i * sizeof(uint64_t)))) = t2;
			}
		}
	};

	template <uint64_t S, unsigned long long F, unsigned long long FL>
	class obfuscated_string
	{
	private:
		char obfuscated[S];

	public:
		__forceinline void set(const char* input)
		{
			uint64_t t1;
			uint64_t t2;

			char whole[S];
			memset(whole, 0, S);

			strcpy_s(whole, input);
			for (auto i = 0; i < S / sizeof(uint64_t); i++)
			{
				t1 = *((uint64_t*)(whole + (i * sizeof(uint64_t))));
				ENCRYPT(t2, t1, F, FL);

				memcpy(obfuscated + (i * sizeof(uint64_t)), &t2, sizeof(t2));
			}
		}

		__forceinline void get(char* output)
		{
			uint64_t t1;
			uint64_t t2;

			char whole[S];
			memset(whole, 0, S);

			bool has_null = false;
			for (auto i = 0; i < S / sizeof(uint64_t) && !has_null; i++)
			{
				t1 = *((uint64_t*)(obfuscated + (i * sizeof(uint64_t))));
				DECRYPT(t2, t1, F, FL);

				memcpy(whole + (i * sizeof(uint64_t)), &t2, sizeof(t2));
			}

			strcpy_s(output, S, whole);
		}

	public:
		__forceinline obfuscated_string(const char* c)
		{
			set(c);
		}
	};

	struct obfuscated_str_arg
	{
		const char* arg;

	public:
		__forceinline obfuscated_str_arg(const char* arg)
		{
			this->arg = arg;
		}
	};

	template <typename T, unsigned long long F, unsigned long long FL>
	class obfuscated_prim64
	{
	private:
		uint64_t obfuscated;

	public:
		__forceinline void set(T val)
		{
			uint64_t tk = *((uint64_t*)__TIME__);

			uint64_t obf;
			ENCRYPT(obf, (uint64_t)val, F ^ tk, FL);
			this->obfuscated = obf;
		}

		__forceinline T get()
		{
			uint64_t tk = *((uint64_t*)__TIME__);

			uint64_t deob;
			DECRYPT(deob, obfuscated, F ^ tk, FL);
			return (T)deob;
		}

		__forceinline obfuscated_prim64(T val)
		{
			set(val);
		}

		__forceinline obfuscated_prim64() : obfuscated_prim64((T)nullptr)
		{

		}

		__forceinline operator T() { return get(); }

		__forceinline obfuscated_prim64<T, F, FL> operator/(int val)
		{
			auto dec = get();
			dec /= val;
			return obfuscated_prim64<T, F, FL>(dec);
		}

		__forceinline obfuscated_prim64<T, F, FL> operator*(int val)
		{
			auto dec = get();
			dec *= val;
			return obfuscated_prim64<T, F, FL>(dec);
		}

		__forceinline obfuscated_prim64<T, F, FL> operator&(int val)
		{
			auto dec = get();
			dec &= val;
			return obfuscated_prim64<T, F, FL>(dec);
		}

		__forceinline obfuscated_prim64<T, F, FL> operator++(int val)
		{
			auto dec = get();
			dec += val;
			return obfuscated_prim64<T, F, FL>(dec);
		}

		__forceinline obfuscated_prim64<T, F, FL>& operator/=(int val)
		{
			auto dec = get();
			dec /= val;
			set(dec);
			return *this;
		}

		__forceinline obfuscated_prim64<T, F, FL>& operator*=(int val)
		{
			auto dec = get();
			dec *= val;
			set(dec);
			return *this;
		}

		__forceinline obfuscated_prim64<T, F, FL>& operator+=(int val)
		{
			auto dec = get();
			dec += val;
			set(dec);
			return *this;
		}

		__forceinline obfuscated_prim64<T, F, FL> operator|=(int val)
		{
			auto dec = get();
			dec |= val;
			set(dec);
			return *this;
		}

		__forceinline obfuscated_prim64<T, F, FL> operator++()
		{
			return obfuscated_prim64<T, F, FL>(get()) + 1;
		}
	};
}