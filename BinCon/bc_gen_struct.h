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
		char padding_0[4];
		obfuscated_prim64<packed_import_type, 0x1337, __LINE__> type;
		char padding_1[43];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> rva;
		char padding_2[78];
		obfuscated_prim64<uint32_t, 0x1337, __LINE__> ordinal;
		char padding_3[74];
		obfuscated_string<256, 0x1337, __LINE__> name;
		char padding_4[4];
		obfuscated_string<256, 0x1337, __LINE__> mod;
	};

	struct packed_section
	{
		char padding_0[89];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> characteristics;
		char padding_1[51];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> rva;
		char padding_2[62];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> off_to_data;
		char padding_3[89];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> size_of_data;
	};

	struct packed_resource
	{
		char padding_0[18];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> size_of_data;
		char padding_1[98];
		obfuscated_prim64<uint16_t, 0x1337, __LINE__> id;
		char padding_2[44];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> off_to_data;
	};

	struct packed_reloc
	{
		char padding_0[86];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> rva;
	};

	struct packed_tls_callback
	{
		char padding_0[6];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> callback;
	};

	struct counted_element
	{
		char padding_0[80];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> off;
		char padding_1[21];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> num_elements;
	};

	struct packed_app
	{
		char padding_0[64];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> ep;
		char padding_1[85];
		counted_element off_to_iat;
		char padding_2[5];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> preferred_base;
		char padding_3[83];
		counted_element off_to_relocs;
		char padding_4[56];
		obfuscated_prim64<uint8_t, 0x1337, __LINE__> options;
		char padding_5[63];
		counted_element off_to_headers;
		char padding_6[87];
		counted_element off_to_resources;
		char padding_7[45];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> size_of_img;
		char padding_8[19];
		counted_element off_to_sections;
	};

}
#pragma pack(pop)
