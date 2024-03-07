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
		char padding_0[29];
		obfuscated_prim64<uint32_t, 0x1337, __LINE__> ordinal;
		char padding_1[84];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> rva;
		char padding_2[91];
		obfuscated_prim64<packed_import_type, 0x1337, __LINE__> type;
		char padding_3[44];
		obfuscated_string<256, 0x1337, __LINE__> name;
		char padding_4[44];
		obfuscated_string<256, 0x1337, __LINE__> mod;
	};

	struct packed_section
	{
		char padding_0[33];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> size_of_data;
		char padding_1[37];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> off_to_data;
		char padding_2[47];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> characteristics;
		char padding_3[2];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> rva;
	};

	struct packed_resource
	{
		char padding_0[15];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> size_of_data;
		char padding_1[79];
		obfuscated_prim64<uint16_t, 0x1337, __LINE__> id;
		char padding_2[23];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> off_to_data;
	};

	struct packed_reloc
	{
		char padding_0[36];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> rva;
	};

	struct packed_tls_callback
	{
		char padding_0[87];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> callback;
	};

	struct counted_element
	{
		char padding_0[27];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> num_elements;
		char padding_1[23];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> off;
	};

	struct packed_app
	{
		char padding_0[15];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> ep;
		char padding_1[52];
		obfuscated_prim64<uint8_t, 0x1337, __LINE__> options;
		char padding_2[37];
		counted_element off_to_iat;
		char padding_3[93];
		counted_element off_to_headers;
		char padding_4[70];
		counted_element off_to_resources;
		char padding_5[61];
		counted_element off_to_sections;
		char padding_6[85];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> size_of_img;
		char padding_7[97];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> preferred_base;
		char padding_8[3];
		counted_element off_to_relocs;
	};

}
#pragma pack(pop)
