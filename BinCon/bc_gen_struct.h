#pragma once
#include "bc_var.h"

namespace bc
{
#pragma pack(push, 1)
	enum class packed_import_type
	{
		ordinal,
		name,
	};

	struct packed_import
	{
		char padding_0[2];
		obfuscated_prim64<uint64_t> rva;
		char padding_1[99];
		obfuscated_prim64<packed_import_type> type;
		char padding_2[35];
		obfuscated_prim64<uint32_t> ordinal;
		char padding_3[77];
		obfuscated_string<256> name;
		char padding_4[65];
		obfuscated_string<256> mod;
	};

	struct packed_section
	{
		char padding_0[15];
		obfuscated_prim64<uint64_t> size_of_data;
		char padding_1[65];
		obfuscated_prim64<uint64_t> characteristics;
		char padding_2[32];
		obfuscated_prim64<uint64_t> rva;
		char padding_3[57];
		obfuscated_prim64<uint64_t> off_to_data;
	};

	struct packed_reloc
	{
		char padding_0[83];
		obfuscated_prim64<uint64_t> rva;
	};

	struct counted_element
	{
		char padding_0[43];
		obfuscated_prim64<uint64_t> off;
		char padding_1[14];
		obfuscated_prim64<uint64_t> num_elements;
	};

	struct packed_app
	{
		char padding_0[50];
		obfuscated_prim64<uint8_t> options;
		char padding_1[44];
		counted_element off_to_relocs;
		char padding_2[69];
		obfuscated_prim64<uint64_t> preferred_base;
		char padding_3[65];
		counted_element off_to_iat;
		char padding_4[89];
		counted_element off_to_sections;
		char padding_5[25];
		obfuscated_prim64<uint64_t> size_of_img;
		char padding_6[38];
		obfuscated_prim64<uint64_t> ep;
	};

}
#pragma pack(pop)
