#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <fstream>

enum class obfuscation_type : int8_t
{
    bswap = 0,
    xxor = 1,
    m_inverse = 2,
    max
};

struct obfuscation_pass
{
    obfuscation_type type;
    uint64_t args[3];

    obfuscation_pass(obfuscation_type type, uint64_t arg_a = 0, uint64_t arg_b = 0, uint64_t arg_c = 0)
    {
        this->type = type;
        args[0] = arg_a;
        args[1] = arg_b;
        args[2] = arg_c;
    }
};

uint64_t mul_inv(uint64_t n, uint64_t mod)
{
    uint64_t a = mod, b = a, c = 0, d = 0, e = 1, f, g;
    for (n *= a > 1; n > 1 && (n *= a > 0); e = g, c = (c & 3) | (c & 1) << 2) {
        g = d, d *= n / (f = a);
        a = n % a, n = f;
        c = (c & 6) | (c & 2) >> 1;
        f = c > 1 && c < 6;
        c = (c & 5) | (f || e > d ? (c & 4) >> 1 : ~c & 2);
        d = f ? d + e : e > d ? e - d : d - e;
    }

    return n ? c & 4 ? b - e : e : 0;
}

uint64_t build_bit_mask(int num_bits, int off)
{
    uint64_t mask = 0;
    for (int i = 0; i < num_bits; i++)
    {
        mask |= (1ull << (off + i));
    }
    return mask;
}

void generate_macro(std::ostringstream& o, std::string macro)
{
    o << "#define " << macro << "(O, X) ";
}

void generate_header(std::ostringstream& o)
{
    o << "O = X; \\" << std::endl;
    o << "{  \\" << std::endl;
    o << "\tuint64_t __a; \\" << std::endl;
    o << "\tuint64_t __b; \\" << std::endl;
}

void generate_footer(std::ostringstream& o)
{
    o << "}" << std::endl;
}

void generate_bit_swap(std::ostringstream& o, int num_bits, int a, int b)
{
    o << "\t__a = (O & " << build_bit_mask(num_bits, a) << ") >> " << a << "ull; \\" << std::endl;
    o << "\t__b = (O & " << build_bit_mask(num_bits, b) << ") >> " << b << "ull; \\" << std::endl;
    o << "\tO &= ~" << build_bit_mask(num_bits, a) << "; \\" << std::endl;
    o << "\tO &= ~" << build_bit_mask(num_bits, b) << "; \\" << std::endl;
    o << "\tO |= __a << " << b << "ull; \\" << std::endl;
    o << "\tO |= __b << " << a << "ull; \\" << std::endl;
}

void generate_inverse(std::ostringstream& o, uint64_t v1, uint64_t v2)
{
    o << "\t*((uint16_t*)&O) *= " << v1 << "; \\" << std::endl;
    o << "\t*((uint16_t*)&O + 1) *= " << v2 << "; \\" << std::endl;
}

void generate_xor(std::ostringstream& o, uint64_t v)
{
    o << "\tO ^= " << v << "; \\" << std::endl;
}

void add_random(std::vector<obfuscation_pass>& passes)
{
    auto type = (obfuscation_type)(rand() % (int)obfuscation_type::max);
    switch (type)
    {
    case obfuscation_type::bswap:
    {
        auto bit_count = ((rand() % 28) + 1);
        auto off_a = (rand() % (32 - bit_count));
        auto off_b = ((rand() % (32 - bit_count)) + 32);
        passes.push_back(obfuscation_pass(type, bit_count, off_a, off_b));
        break;
    }
    case obfuscation_type::xxor:
    {
        auto v = ((uint64_t)rand() << 32) | (uint64_t)rand();
        passes.push_back(obfuscation_pass(type, v));
        break;
    }
    case obfuscation_type::m_inverse:
    {
        auto v1 = ((uint64_t)rand() % 65535);
        auto v2 = ((uint64_t)rand() % 65535);
        auto mod = 0xfff00000 + ((rand() % 10) * 0x10000);

        do
        {
            v1 = ((uint64_t)rand() % 65535);
        } while (!mul_inv(v1, mod));

        do
        {
            v2 = ((uint64_t)rand() % 65535);
        } while (!mul_inv(v2, mod));

        passes.push_back(obfuscation_pass(type, v2, mod, v1));
        break;
    }
    }
}

std::string generate_encrypt(std::vector<obfuscation_pass> passes)
{
    std::ostringstream ss;
    generate_macro(ss, "ENCRYPT");
    generate_header(ss);
    for (auto pass : passes)
    {
        switch (pass.type)
        {
        case obfuscation_type::bswap:
            generate_bit_swap(ss, pass.args[0], pass.args[1], pass.args[2]);
            break;
        case obfuscation_type::xxor:
            generate_xor(ss, pass.args[0]);
            break;
        case obfuscation_type::m_inverse:
            generate_inverse(ss, pass.args[2], pass.args[0]);
            break;
        }
    }
    generate_footer(ss);
    return ss.str();
}

std::string generate_decrypt(std::vector<obfuscation_pass> passes)
{
    std::ostringstream ss;
    std::reverse(passes.begin(), passes.end());

    generate_macro(ss, "DECRYPT");
    generate_header(ss);
    for (auto pass : passes)
    {
        switch (pass.type)
        {
        case obfuscation_type::bswap:
            generate_bit_swap(ss, pass.args[0], pass.args[1], pass.args[2]);
            break;
        case obfuscation_type::xxor:
            generate_xor(ss, pass.args[0]);
            break;
        case obfuscation_type::m_inverse:
            generate_inverse(ss, mul_inv(pass.args[2], pass.args[1]), mul_inv(pass.args[0], pass.args[1]));
            break;
        }
    }
    generate_footer(ss);
    return ss.str();
}

int main()
{
    std::srand(std::time(0));
    srand(std::time(0));

    std::vector<obfuscation_pass> passes;
    for (int i = 0; i < 4; i++)
    {
        add_random(passes);
    }

    std::cout << generate_encrypt(passes);
    std::cout << generate_decrypt(passes);

    std::ofstream of("bc_gen.h", std::ios::out);
    of << "#pragma once\n" << std::endl;
    of << generate_encrypt(passes) << std::endl;
    of << generate_decrypt(passes) << std::endl;
    of.close();
}
