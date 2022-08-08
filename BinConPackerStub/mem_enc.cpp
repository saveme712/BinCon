#include <Windows.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <map>

#include <bc_stub.h>
#include <bc_peb.h>
#include <bc_util.h>
#include <bc_thirdparty.h>
#include <bc_integrity.h>
#include <bc_memory.h>
#include <bc_windows.h>

#include <xorstr.hpp>

#include <Zydis/Zydis.h>

namespace bc
{
    struct encrypted_ptr
    {
        obfuscated_prim64<uint64_t> real;
        obfuscated_prim64<size_t> size;

        __forceinline encrypted_ptr(uint64_t real, size_t size)
        {
            this->real = real;
            this->size = size;
        }

        __forceinline encrypted_ptr() : encrypted_ptr(0, 0)
        {

        }
    };

    static std::map<uint64_t, encrypted_ptr> encrypted_ptr_map;
    static uint64_t alloc_base = 0xff00000000000000ull;

    uint64_t allocate_encrypted(size_t size)
    {
        auto v = (uint64_t)malloc(size);
        
        auto enc_ptr = alloc_base; 
        encrypted_ptr_map[enc_ptr] = encrypted_ptr(v, size);

        alloc_base += size;
        return enc_ptr;
    }

    void free_encrypted(uint64_t addr)
    {
        encrypted_ptr_map.erase(addr);
    }

    uint64_t find_encrypted(uint64_t fake_search)
    {
        for (auto& kv : encrypted_ptr_map)
        {
            auto fake_addr = kv.first;
            auto real_addr = kv.second.real.get();
            if (fake_search >= fake_addr && fake_search < (fake_addr + kv.second.size.get()))
            {
                return real_addr + (fake_search - fake_addr);
            }
        }
    }

    /// <summary>
    /// Retrieves the provided register from the context.
    /// </summary>
    static uint64_t retrieve_context(PCONTEXT context, ZydisRegister reg)
    {
        switch (reg)
        {
        case ZydisRegister::ZYDIS_REGISTER_RAX:
            return context->Rax;
        case ZydisRegister::ZYDIS_REGISTER_RCX:
            return context->Rcx;
        case ZydisRegister::ZYDIS_REGISTER_RDX:
            return context->Rdx;
        case ZydisRegister::ZYDIS_REGISTER_RBX:
            return context->Rbx;
        case ZydisRegister::ZYDIS_REGISTER_R8:
            return context->R8;
        case ZydisRegister::ZYDIS_REGISTER_R9:
            return context->R9;
        case ZydisRegister::ZYDIS_REGISTER_R10:
            return context->R10;
        case ZydisRegister::ZYDIS_REGISTER_R11:
            return context->R11;
        case ZydisRegister::ZYDIS_REGISTER_R12:
            return context->R12;
        case ZydisRegister::ZYDIS_REGISTER_R13:
            return context->R13;
        case ZydisRegister::ZYDIS_REGISTER_R14:
            return context->R14;
        case ZydisRegister::ZYDIS_REGISTER_R15:
            return context->R15;
        }
        return 0;
    }

    /// <summary>
    /// Stores the provided register into the context.
    /// </summary>
    static void update_context(PCONTEXT context, ZydisRegister reg, uint64_t val)
    {
        switch (reg)
        {
        case ZydisRegister::ZYDIS_REGISTER_RAX:
            context->Rax = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_RCX:
            context->Rcx = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_RDX:
            context->Rdx = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_RBX:
            context->Rbx = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_R8:
            context->R8 = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_R9:
            context->R9 = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_R10:
            context->R10 = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_R11:
            context->R11 = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_R12:
            context->R12 = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_R13:
            context->R13 = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_R14:
            context->R14 = val;
            break;
        case ZydisRegister::ZYDIS_REGISTER_R15:
            context->R15 = val;
            break;
        }
    }

    /// <summary>
    /// Attempts to emulate an encrypted memory instruction.
    /// </summary>
    bool emulate_encrypted_ins(PCONTEXT context, void* ins)
    {
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZydisAddressWidth::ZYDIS_ADDRESS_WIDTH_64);

        ZydisDecodedInstruction instruction;
        auto err = ZydisDecoderDecodeBuffer(&decoder, ins, 15, &instruction);
        auto any = false;
        if (ZYAN_SUCCESS(err))
        {
            for (auto i = 0; i < instruction.operand_count; i++)
            {
                auto& op = instruction.operands[i];
                if (op.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    auto base = op.mem.base;
                    auto base_r = retrieve_context(context, base);

                    if (auto translated = find_encrypted(base_r))
                    {
                        update_context(context, op.mem.base, translated);
                        any = true;
                    }
                }
            }
        }

        return any;
    }
}