#pragma once
#include <cstdint>
#include <intrin.h>
#include "bc_gen.h"

namespace bc
{
	template <typename T>
	class obfuscated_prim64
	{
	private:
		uint64_t obfuscated;

	public:
		__forceinline void set(T val)
		{
			uint64_t obf;
			ENCRYPT(obf, (uint64_t)val);
			this->obfuscated = obf;
		}

		__forceinline T get()
		{
			uint64_t deob;
			DECRYPT(deob, obfuscated);
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

		__forceinline obfuscated_prim64<T> operator/(int val)
		{
			auto dec = get();
			dec /= val;
			set(dec);
			return obfuscated_prim64<T>(dec);
		}

		__forceinline obfuscated_prim64<T> operator*(int val)
		{
			auto dec = get();
			dec *= val;
			return obfuscated_prim64<T>(dec);
		}

		__forceinline obfuscated_prim64<T> operator++(int val)
		{
			auto dec = get();
			dec += val;
			return obfuscated_prim64<T>(dec);
		}

		__forceinline obfuscated_prim64<T> operator++()
		{
			return obfuscated_prim64<T>(get()) + 1;
		}
	};
}