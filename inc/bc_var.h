#pragma once
#include <cstdint>
#include <intrin.h>

#define ENCRYPT(X) (_rotr64(X ^ 0x812348912894ull, 4))
#define DECRYPT(X) (_rotl64(X, 4) ^ 0x812348912894ull)

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
			this->obfuscated = ENCRYPT((uint64_t)val);
		}

		__forceinline T get()
		{
			return (T)DECRYPT(obfuscated);
		}

		__forceinline obfuscated_prim64(T val)
		{
			set(val);
		}

		__forceinline obfuscated_prim64() : obfuscated_prim64((T)nullptr)
		{

		}

		__forceinline operator T() { return get(); }
		__forceinline obfuscated_prim64<T> operator++(int val)
		{
			auto dec = get();
			dec += val;
			set(dec);
			return *this;
		}

		__forceinline obfuscated_prim64<T> operator++()
		{
			return *this + 1;
		}
	};
}