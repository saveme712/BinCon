#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <fstream>

#include <random>

#define PERMUTATIONS 30

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
    uint64_t args[5];

    obfuscation_pass(obfuscation_type type, uint64_t arg_a = 0, uint64_t arg_b = 0, uint64_t arg_c = 0, uint64_t arg_d = 0, uint64_t arg_e = 0)
    {
        this->type = type;
        args[0] = arg_a;
        args[1] = arg_b;
        args[2] = arg_c;
        args[3] = arg_d;
        args[4] = arg_e;
    }
};

struct struct_field
{
    const char* type;
    const char* name;

    struct_field(const char* type, const char* name)
    {
        this->type = type;
        this->name = name;
    }
    struct_field(const char* name)
    {
        this->type = "";
        this->name = name;
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
    o << "#define " << macro << "(O, X, F, FL) ";
}

void generate_header(std::ostringstream& o)
{
    o << "\tO = X; \\" << std::endl;
    o << "\t{  \\" << std::endl;
    o << "\t\tuint64_t __a; \\" << std::endl;
    o << "\t\tuint64_t __b; \\" << std::endl;
}

void generate_footer(std::ostringstream& o)
{
    o << "}" << std::endl;
}

void generate_bit_swap(std::ostringstream& o, int num_bits, int a, int b)
{
    o << "\t\t__a = (O & " << build_bit_mask(num_bits, a) << ") >> " << a << "ull; \\" << std::endl;
    o << "\t\t__b = (O & " << build_bit_mask(num_bits, b) << ") >> " << b << "ull; \\" << std::endl;
    o << "\t\tO &= ~" << build_bit_mask(num_bits, a) << "; \\" << std::endl;
    o << "\t\tO &= ~" << build_bit_mask(num_bits, b) << "; \\" << std::endl;
    o << "\t\tO |= __a << " << b << "ull; \\" << std::endl;
    o << "\t\tO |= __b << " << a << "ull; \\" << std::endl;
}

void generate_inverse(std::ostringstream& o, uint64_t v1, uint64_t v2, uint64_t v3, uint64_t v4)
{
    o << "\t\t*((uint16_t*)&O) *= " << v1 << "; \\" << std::endl;
    o << "\t\t*((uint16_t*)&O + 1) *= " << v2 << "; \\" << std::endl;
    o << "\t\t*((uint16_t*)&O + 2) *= " << v3 << "; \\" << std::endl;
    o << "\t\t*((uint16_t*)&O + 3) *= " << v4 << "; \\" << std::endl;
}

void generate_xor(std::ostringstream& o, uint64_t v)
{
    o << "\t\tO ^= " << v << "; \\" << std::endl;
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
        auto v3 = ((uint64_t)rand() % 65535);
        auto v4 = ((uint64_t)rand() % 65535);
        auto mod = 0xfff00000 + ((rand() % 10) * 0x10000);

        do
        {
            v1 = ((uint64_t)rand() % 65535);
        } while (!mul_inv(v1, mod));

        do
        {
            v2 = ((uint64_t)rand() % 65535);
        } while (!mul_inv(v2, mod));

        do
        {
            v3 = ((uint64_t)rand() % 65535);
        } while (!mul_inv(v3, mod));

        do
        {
            v4 = ((uint64_t)rand() % 65535);
        } while (!mul_inv(v4, mod));


        passes.push_back(obfuscation_pass(type, v2, mod, v1, v3, v4));
        break;
    }
    }
}

std::string generate_encrypt(std::vector<std::vector<obfuscation_pass>> passes, std::string name)
{
    std::ostringstream ss;
    generate_macro(ss, name);
    generate_header(ss);

    for (auto i = 0; i < passes.size(); i++)
    {
        if (i > 0)
        {
            ss << "\t}" << " \\" << std::endl;
        }

        ss << "\t";

        if (i > 0)
        {
            ss << "else ";
        }

        if (i != (passes.size() - 1))
        {
            ss << "if ((FL % " << (passes.size() - i - 1) << ") == 0)";
        }

        ss << " \\" << std::endl;
        ss << "\t{" << " \\" << std::endl;

        for (auto pass : passes[i])
        {
            switch (pass.type)
            {
            case obfuscation_type::bswap:
                generate_bit_swap(ss, (int)pass.args[0], (int)pass.args[1], (int)pass.args[2]);
                break;
            case obfuscation_type::xxor:
                generate_xor(ss, pass.args[0]);
                break;
            case obfuscation_type::m_inverse:
                generate_inverse(ss, pass.args[2], pass.args[0], pass.args[3], pass.args[4]);
                break;
            }
        }

        if (i == (passes.size() - 1))
        {
            ss << "\t}" << " \\" << std::endl;
        }
    }

    
    generate_footer(ss);
    return ss.str();
}

std::string generate_decrypt(std::vector<std::vector<obfuscation_pass>> passes, std::string name)
{
    std::ostringstream ss;
    
    generate_macro(ss, name);
    generate_header(ss);

    for (auto i = 0; i < passes.size(); i++)
    {
        if (i > 0)
        {
            ss << "\t}" << " \\" << std::endl;
        }

        ss << "\t";

        if (i > 0)
        {
            ss << "else ";
        }

        if (i != (passes.size() - 1))
        {
            ss << "if ((FL % " << (passes.size() - i - 1) << ") == 0)";
        }

        ss << " \\" << std::endl;
        ss << "\t{" << " \\" << std::endl;

        auto current_passes = passes[i];
        std::reverse(current_passes.begin(), current_passes.end());

        for (auto& pass : current_passes)
        {
            switch (pass.type)
            {
            case obfuscation_type::bswap:
                generate_bit_swap(ss, (int)pass.args[0], (int)pass.args[1], (int)pass.args[2]);
                break;
            case obfuscation_type::xxor:
                generate_xor(ss, pass.args[0]);
                break;
            case obfuscation_type::m_inverse:
                generate_inverse(ss, mul_inv(pass.args[2], pass.args[1]), mul_inv(pass.args[0], pass.args[1]), mul_inv(pass.args[3], pass.args[1]), mul_inv(pass.args[4], pass.args[1]));
                break;
            }
        }

        if (i == (passes.size() - 1))
        {
            ss << "\t}" << " \\" << std::endl;
        }
    }

    generate_footer(ss);
    return ss.str();
}

std::string generate_struct(const char* struct_name, std::vector<struct_field> fields)
{
    std::random_device rd;
    std::mt19937 rng(rd());
    std::shuffle(fields.begin(), fields.end(), rng);

    auto pad_index = 0;
    std::ostringstream ss;
    ss << "\tstruct " << struct_name << std::endl;
    ss << "\t{" << std::endl;
    for (auto& field : fields)
    {
        ss << "\t\tchar padding_" << pad_index++ << "[" << ((rand() % 100) + 1) << "];" << std::endl;
        ss << "\t\t" << field.type << " " << field.name << ";" << std::endl;
    }
    ss << "\t};" << std::endl << std::endl;
    return ss.str();
}

std::string generate_enum(const char* struct_name, std::vector<struct_field> fields)
{
    std::random_device rd;
    std::mt19937 rng(rd());
    std::shuffle(fields.begin(), fields.end(), rng);

    auto pad_index = 0;
    std::ostringstream ss;
    ss << "\tenum class " << struct_name << std::endl;
    ss << "\t{" << std::endl;
    for (auto& field : fields)
    {
        ss << "\t\t" << field.name << "," << std::endl;
    }
    ss << "\t};" << std::endl << std::endl;
    return ss.str();
}


int main()
{
    std::srand((unsigned int)std::time(0));
    srand((unsigned int)std::time(0));

    std::vector<std::vector<obfuscation_pass>> passes(PERMUTATIONS);
    for (int i = 0; i < PERMUTATIONS; i++)
    {
        add_random(passes[i]);
    }

    std::ofstream gen_of("bc_gen.h", std::ios::out);
    gen_of << "#pragma once" << std::endl;
    gen_of << "#include <cstdint>" << std::endl;
    gen_of << "extern uint32_t dyn_key_32;" << std::endl;
    gen_of << "extern uint64_t dyn_key_64;" << std::endl;
    gen_of << generate_encrypt(passes, "ENCRYPT") << std::endl;
    gen_of << generate_decrypt(passes, "DECRYPT") << std::endl;
    gen_of << generate_encrypt(passes, "ENCRYPTM") << std::endl;
    gen_of << generate_decrypt(passes, "DECRYPTM") << std::endl;
    gen_of.close();

    std::ofstream gens_of("bc_gen_struct.h", std::ios::out);
    gens_of << "#pragma once" << std::endl;
    gens_of << "#include \"bc_var.h\"" << std::endl << std::endl;
    gens_of << "namespace bc" << std::endl;
    gens_of << "{" << std::endl;
    gens_of << "#pragma pack(push, 1)" << std::endl;

    gens_of << generate_enum("packed_import_type", { { "name" }, { "ordinal"} });

    gens_of << generate_struct("packed_import", {
        {"obfuscated_prim64<packed_import_type, 0x1337, __LINE__>", "type"},
        {"obfuscated_string<256, 0x1337, __LINE__>", "mod"},
        {"obfuscated_string<256, 0x1337, __LINE__>", "name"},
        {"obfuscated_prim64<uint32_t, 0x1337, __LINE__>", "ordinal"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "rva"}
        });

    gens_of << generate_struct("packed_section", {
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "rva"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "size_of_data"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "off_to_data"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "characteristics"}
        });

    gens_of << generate_struct("packed_resource", {
        {"obfuscated_prim64<uint16_t, 0x1337, __LINE__>", "id"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "off_to_data"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "size_of_data"},
        });

    gens_of << generate_struct("packed_reloc", {
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "rva"}
        });

    gens_of << generate_struct("packed_tls_callback", {
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "callback"}
        });

    gens_of << generate_struct("counted_element", {
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "num_elements"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "off"}
        });

    gens_of << generate_struct("packed_app", {
        {"obfuscated_prim64<uint8_t, 0x1337, __LINE__>", "options"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "size_of_img"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "size_of_app"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "preferred_base"},
        {"obfuscated_prim64<uint64_t, 0x1337, __LINE__>", "ep"},
        {"counted_element", "off_to_relocs"},
        {"counted_element", "off_to_iat"},
        {"counted_element", "off_to_sections"},
        {"counted_element", "off_to_resources"},
        {"counted_element", "off_to_headers"}
        });

    gens_of << "}" << std::endl;
    gens_of << "#pragma pack(pop)" << std::endl;
    gens_of.close();

}
