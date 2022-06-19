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
		char padding_0[45];
		obfuscated_prim64<uint64_t> rva;
		char padding_1[65];
		obfuscated_prim64<uint32_t> ordinal;
		char padding_2[68];
		obfuscated_prim64<packed_import_type> type;
		char padding_3[18];
		obfuscated_string<256> mod;
		char padding_4[9];
		obfuscated_string<256> name;
	};

	struct packed_section
	{
		char padding_0[100];
		obfuscated_prim64<uint64_t> size_of_data;
		char padding_1[81];
		obfuscated_prim64<uint64_t> rva;
		char padding_2[40];
		obfuscated_prim64<uint64_t> off_to_data;
	};

	struct packed_reloc
	{
		char padding_0[62];
		obfuscated_prim64<uint64_t> rva;
	};

	struct counted_element
	{
		char padding_0[43];
		obfuscated_prim64<uint64_t> num_elements;
		char padding_1[34];
		obfuscated_prim64<uint64_t> off;
	};

	struct packed_app
	{
		char padding_0[3];
		counted_element off_to_relocs;
		char padding_1[94];
		counted_element off_to_iat;
		char padding_2[100];
		obfuscated_prim64<uint8_t> options;
		char padding_3[32];
		obfuscated_prim64<uint64_t> size_of_img;
		char padding_4[78];
		counted_element off_to_sections;
		char padding_5[39];
		obfuscated_prim64<uint64_t> preferred_base;
		char padding_6[72];
		obfuscated_prim64<uint64_t> ep;
	};

}
#pragma pop()
