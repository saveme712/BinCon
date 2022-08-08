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
    static std::map<uint64_t, bool> encrypted_ptr_map;

    /// <summary>
    /// Decrypts a pointer.
    /// </summary>
    static __forceinline uint64_t decrypt_ptr(uint64_t ptr)
    {
        uint64_t dec;
        DECRYPTM(dec, ptr);
        return dec;
    }

    /// <summary>
    /// Encrypts a pointer.
    /// </summary>
    uint64_t encrypt_ptr(uint64_t ptr)
    {
        uint64_t enc;
        ENCRYPTM(enc, ptr);
        encrypted_ptr_map[enc] = true;
        return enc;
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
        if (ZYAN_SUCCESS(err))
        {
            uint64_t src;

            if (instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_MOV)
            {
                if (instruction.operands[0].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    auto base = instruction.operands[0].mem.base;
                    auto base_r = retrieve_context(context, base);
                    auto src_r = retrieve_context(context, instruction.operands[1].reg.value);

                    auto off = 0ull;
                    if (instruction.operands[0].mem.disp.has_displacement)
                    {
                        off += instruction.operands[0].mem.disp.value;
                    }

                    if (encrypted_ptr_map.find(base_r) != encrypted_ptr_map.end())
                    {
                        auto dec = decrypt_ptr(base_r) + off;
                        memcpy((void*)dec, &src_r, instruction.operands[0].size / 8);

                        context->Rip += instruction.length;
                        return true;
                    }
                }
                else if (instruction.operands[0].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    auto base = instruction.operands[1].mem.base;
                    auto base_r = retrieve_context(context, base);

                    auto off = 0ull;
                    if (instruction.operands[1].mem.disp.has_displacement)
                    {
                        off += instruction.operands[1].mem.disp.value;
                    }

                    if (encrypted_ptr_map.find(base_r) != encrypted_ptr_map.end())
                    {
                        auto dec = decrypt_ptr(base_r) + off;
                        auto read = 0ull;

                        memcpy(&read, (void*)dec, instruction.operands[0].size / 8);
                        update_context(context, instruction.operands[0].reg.value, read);

                        context->Rip += instruction.length;
                        return true;
                    }
                }
            }
        }

        return false;
    }
}