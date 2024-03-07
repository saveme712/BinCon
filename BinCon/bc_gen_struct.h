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
		char padding_0[14];
		obfuscated_string<256, 0x1337, __LINE__> name;
		char padding_1[7];
		obfuscated_prim64<packed_import_type, 0x1337, __LINE__> type;
		char padding_2[13];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> rva;
		char padding_3[65];
		obfuscated_prim64<uint32_t, 0x1337, __LINE__> ordinal;
		char padding_4[31];
		obfuscated_string<256, 0x1337, __LINE__> mod;
	};

	struct packed_section
	{
		char padding_0[60];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> size_of_data;
		char padding_1[55];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> rva;
		char padding_2[53];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> off_to_data;
		char padding_3[37];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> characteristics;
	};

	struct packed_resource
	{
		char padding_0[60];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> size_of_data;
		char padding_1[11];
		obfuscated_prim64<uint16_t, 0x1337, __LINE__> id;
		char padding_2[76];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> off_to_data;
	};

	struct packed_reloc
	{
		char padding_0[53];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> rva;
	};

	struct packed_tls_callback
	{
		char padding_0[72];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> callback;
	};

	struct counted_element
	{
		char padding_0[81];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> off;
		char padding_1[44];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> num_elements;
	};

	struct packed_app
	{
		char padding_0[51];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> preferred_base;
		char padding_1[28];
		obfuscated_prim64<uint8_t, 0x1337, __LINE__> options;
		char padding_2[15];
		counted_element off_to_iat;
		char padding_3[76];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> size_of_app;
		char padding_4[57];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> size_of_img;
		char padding_5[88];
		counted_element off_to_headers;
		char padding_6[14];
		counted_element off_to_relocs;
		char padding_7[79];
		obfuscated_prim64<uint64_t, 0x1337, __LINE__> ep;
		char padding_8[1];
		counted_element off_to_sections;
		char padding_9[61];
		counted_element off_to_resources;
	};

}
#pragma pack(pop)
