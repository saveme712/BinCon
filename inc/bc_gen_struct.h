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
		char padding_0[94];
		obfuscated_string<256> name;
		char padding_1[2];
		obfuscated_prim64<packed_import_type> type;
		char padding_2[5];
		obfuscated_string<256> mod;
		char padding_3[38];
		obfuscated_prim64<uint32_t> ordinal;
		char padding_4[85];
		obfuscated_prim64<uint64_t> rva;
	};

	struct packed_section
	{
		char padding_0[19];
		obfuscated_prim64<uint64_t> size_of_data;
		char padding_1[96];
		obfuscated_prim64<uint64_t> rva;
		char padding_2[35];
		obfuscated_prim64<uint64_t> characteristics;
		char padding_3[79];
		obfuscated_prim64<uint64_t> off_to_data;
	};

	struct packed_reloc
	{
		char padding_0[45];
		obfuscated_prim64<uint64_t> rva;
	};

	struct counted_element
	{
		char padding_0[98];
		obfuscated_prim64<uint64_t> num_elements;
		char padding_1[14];
		obfuscated_prim64<uint64_t> off;
	};

	struct packed_app
	{
		char padding_0[62];
		counted_element off_to_iat;
		char padding_1[94];
		obfuscated_prim64<uint64_t> preferred_base;
		char padding_2[92];
		obfuscated_prim64<uint8_t> options;
		char padding_3[71];
		obfuscated_prim64<uint64_t> size_of_img;
		char padding_4[78];
		counted_element off_to_relocs;
		char padding_5[50];
		counted_element off_to_sections;
		char padding_6[91];
		obfuscated_prim64<uint64_t> ep;
	};

}
#pragma pack(pop)
