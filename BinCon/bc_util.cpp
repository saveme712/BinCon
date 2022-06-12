#include <bc_util.h>
#include <string>

namespace bc
{
	void ascii_to_wide(const char* in, wchar_t* out)
	{
		auto len = strlen(in);
		for (auto i = 0; i < len; i++)
		{
			out[i] = (wchar_t)in[i];
		}
		out[len] = L'\0';
	}

	void wide_to_ascii(const wchar_t* in, char* out)
	{
		auto len = wcslen(in);
		for (auto i = 0; i < len; i++)
		{
			out[i] = (char)in[i];
		}
		out[len] = '\0';
	}
}