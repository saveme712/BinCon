#pragma once
#include "bc_var.h"

namespace bc
{
#pragma pack(push, 1)
	enum class packed_import_type
	{
		name,
		ordinal,
	};

	struct packed_import
	{
		char padding_0[15];
		obfuscated_prim64<uint32_t> ordinal;
		char padding_1[94];
		obfuscated_string<256> mod;
		char padding_2[48];
		obfuscated_prim64<uint64_t> rva;
		char padding_3[10];
		obfuscated_string<256> name;
		char padding_4[34];
		obfuscated_prim64<packed_import_type> type;
	};

	struct packed_section
	{
		char padding_0[95];
		obfuscated_prim64<uint64_t> characteristics;
		char padding_1[79];
		obfuscated_prim64<uint64_t> size_of_data;
		char padding_2[94];
		obfuscated_prim64<uint64_t> off_to_data;
		char padding_3[70];
		obfuscated_prim64<uint64_t> rva;
	};

	struct packed_reloc
	{
		char padding_0[79];
		obfuscated_prim64<uint64_t> rva;
	};

	struct counted_element
	{
		char padding_0[40];
		obfuscated_prim64<uint64_t> num_elements;
		char padding_1[41];
		obfuscated_prim64<uint64_t> off;
	};

	struct packed_app
	{
		char padding_0[76];
		obfuscated_prim64<uint64_t> size_of_img;
		char padding_1[42];
		counted_element off_to_relocs;
		char padding_2[17];
		obfuscated_prim64<uint8_t> options;
		char padding_3[69];
		obfuscated_prim64<uint64_t> preferred_base;
		char padding_4[90];
		counted_element off_to_iat;
		char padding_5[89];
		counted_element off_to_sections;
		char padding_6[38];
		obfuscated_prim64<uint64_t> ep;
	};

}
#pragma pack(pop)
