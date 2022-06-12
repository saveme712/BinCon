#pragma once

namespace bc
{
	void ascii_to_wide(const char* in, wchar_t* out);

	void wide_to_ascii(const wchar_t* in, char* out);
}