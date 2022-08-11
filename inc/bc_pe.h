#pragma once
#include <map>
#include <Windows.h>

namespace bc
{
	class pe_validator
	{
	public:
		std::map<uint32_t, uint32_t> section_checksums;

	public:
		bool validate(void* real);

	public:
		static pe_validator map(void* original, void* data);
		static pe_validator map(HMODULE mod);
	};
}