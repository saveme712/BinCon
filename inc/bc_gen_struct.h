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
		char padding_0[34];
		obfuscated_prim64<packed_import_type> type;
		char padding_1[93];
		obfuscated_prim64<uint64_t> rva;
		char padding_2[70];
		obfuscated_prim64<uint32_t> ordinal;
		char padding_3[6];
		obfuscated_string<256> name;
		char padding_4[45];
		obfuscated_string<256> mod;
	};

	struct packed_section
	{
		char padding_0[89];
		obfuscated_prim64<uint64_t> rva;
		char padding_1[9];
		obfuscated_prim64<uint64_t> off_to_data;
		char padding_2[27];
		obfuscated_prim64<uint64_t> characteristics;
		char padding_3[61];
		obfuscated_prim64<uint64_t> size_of_data;
	};

	struct packed_reloc
	{
		char padding_0[48];
		obfuscated_prim64<uint64_t> rva;
	};

	struct counted_element
	{
		char padding_0[73];
		obfuscated_prim64<uint64_t> num_elements;
		char padding_1[65];
		obfuscated_prim64<uint64_t> off;
	};

	struct packed_app
	{
		char padding_0[33];
		counted_element off_to_iat;
		char padding_1[81];
		obfuscated_prim64<uint64_t> preferred_base;
		char padding_2[64];
		counted_element off_to_relocs;
		char padding_3[9];
		obfuscated_prim64<uint8_t> options;
		char padding_4[24];
		counted_element off_to_sections;
		char padding_5[37];
		obfuscated_prim64<uint64_t> size_of_img;
		char padding_6[43];
		obfuscated_prim64<uint64_t> ep;
	};

}
#pragma pop()
