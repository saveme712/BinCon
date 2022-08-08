# BinCon
A library to assist with memory &amp; code protection. This is not meant to be a drop in replacement for anything, but as an example for how to provide an 
increased layer of protection on top of virtualization or code mutation.

The example project provides an example of a simple console application hardened against memory scans, memory modifications, debuggers, and other things.

# Features

## Obfuscated Variables
Support for transparent obfuscation of native data types, including pointers, and integers.

## VEH Pointer Obfuscation
Support for transparent obfuscation of pointers, where the decryption is handled by a custom VEH routine that will
emulate the memory read with the real decrypted address.

## Build Time Randomization
The expression used to obfuscate variables will be randomized before a build is started. The file format of the packer is completely randomized.

```C++
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
```

All projects share the same generated files, which can be leveraged for communication from app <-> packer. The packer has a provided communication channel with a hook on `GetProcAddress`. This will
allow you to talk to the packer stub, and request integrity checks, memory re-encryption, pointer encryption, etc.

```C++
(chal_entry*)GetProcAddress((HMODULE)0xBC, xorstr_("pack_interface"))
```

The generated expressions use a mix of XOR, byte swap, and multiplicative inverse obfuscation generated in randomized order.

```C++
#define ENCRYPT(O, X) O = X; \
{  \
	uint64_t __a; \
	uint64_t __b; \
	O ^= 136292197216505; \
	O ^= 130747394438946; \
	__a = (O & 33538048) >> 14ull; \
	__b = (O & 72022409665839104) >> 45ull; \
	O &= ~33538048; \
	O &= ~72022409665839104; \
	O |= __a << 45ull; \
	O |= __b << 14ull; \
	__a = (O & 268435454) >> 1ull; \
	__b = (O & 2305842992033824768) >> 34ull; \
	O &= ~268435454; \
	O &= ~2305842992033824768; \
	O |= __a << 34ull; \
	O |= __b << 1ull; \
}

#define DECRYPT(O, X) O = X; \
{  \
	uint64_t __a; \
	uint64_t __b; \
	__a = (O & 268435454) >> 1ull; \
	__b = (O & 2305842992033824768) >> 34ull; \
	O &= ~268435454; \
	O &= ~2305842992033824768; \
	O |= __a << 34ull; \
	O |= __b << 1ull; \
	__a = (O & 33538048) >> 14ull; \
	__b = (O & 72022409665839104) >> 45ull; \
	O &= ~33538048; \
	O &= ~72022409665839104; \
	O |= __a << 45ull; \
	O |= __b << 14ull; \
	O ^= 130747394438946; \
	O ^= 136292197216505; \
}
```

## Encrypted Sections
Keep your code sections encrypted and unavailable in memory until they're accessed, with periodic re-encryption.

## Memory Allocator
A very poorly made memory allocator that supports randomizing the allocated blocks. Will be redone soon TM.
