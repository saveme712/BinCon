#pragma once
#include <cstdint>
#include <intrin.h>

#define ENCRYPT(X) (_rotr64(X ^ 0x812348912894ull, 4))
#define DECRYPT(X) (_rotl64(X, 4) ^ 0x812348912894ull)

template <typename T>
class ObfuscatedPrimitive64
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

	__forceinline ObfuscatedPrimitive64(T val)
	{
		set(val);
	}

	__forceinline ObfuscatedPrimitive64() : ObfuscatedPrimitive64((T)nullptr)
	{

	}

	__forceinline operator T() { return get(); }
	__forceinline ObfuscatedPrimitive64<T> operator++(int val)
	{
		auto dec = get();
		dec += val;
		set(dec);
		return *this;
	}
	
	__forceinline ObfuscatedPrimitive64<T> operator++()
	{
		return *this + 1;
	}
};