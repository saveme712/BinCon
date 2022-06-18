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
		char padding_0[93];
		obfuscated_prim64<uint64_t> rva;
		char padding_1[11];
		obfuscated_prim64<packed_import_type> type;
		char padding_2[44];
		char mod[256];
		char padding_3[27];
		char name[256];
		char padding_4[65];
		obfuscated_prim64<uint32_t> ordinal;
	};

	struct packed_section
	{
		char padding_0[83];
		obfuscated_prim64<uint64_t> rva;
		char padding_1[52];
		obfuscated_prim64<uint64_t> size_of_data;
		char padding_2[65];
		obfuscated_prim64<uint64_t> off_to_data;
	};

	struct packed_reloc
	{
		char padding_0[15];
		obfuscated_prim64<uint64_t> rva;
	};

	struct counted_element
	{
		char padding_0[1];
		obfuscated_prim64<uint64_t> off;
		char padding_1[1];
		obfuscated_prim64<uint64_t> num_elements;
	};

	struct packed_app
	{
		char padding_0[42];
		obfuscated_prim64<uint64_t> ep;
		char padding_1[3];
		obfuscated_prim64<uint64_t> preferred_base;
		char padding_2[27];
		obfuscated_prim64<uint8_t> options;
		char padding_3[81];
		counted_element off_to_relocs;
		char padding_4[82];
		counted_element off_to_sections;
		char padding_5[85];
		counted_element off_to_iat;
		char padding_6[8];
		obfuscated_prim64<uint64_t> size_of_img;
	};

}
#pragma pop()
