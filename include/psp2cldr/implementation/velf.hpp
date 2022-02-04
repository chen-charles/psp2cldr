/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef VITA_ELF_H
#define VITA_ELF_H

#include <cassert>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

#include <psp2cldr/access_proxy.hpp>
#include <psp2cldr/implementation/arm_elfloader.hpp>
#include <psp2cldr/implementation/logger.hpp>
#include <vita-toolchain/sce-elf.h>

class VELF : public ELFLoader_Base
{
  public:
    VELF(const std::string &filename) : VELF(std::ifstream(filename, std::ios::binary))
    {
    }

    VELF(std::ifstream &&stream) : ELFLoader_Base(std::move(stream))
    {
        if (ehdr.e_type != ET_SCE_RELEXEC)
            throw std::invalid_argument("only SCE Relocatable files are supported");

        if (ehdr.e_shstrndx != SHN_UNDEF)
        {
            auto &strtab_shdr = shdrs[ehdr.e_shstrndx];
            p_strtab = new char[strtab_shdr.sh_size];
            ifs.seekg(strtab_shdr.sh_offset, std::ios::beg);
            ifs.read(p_strtab, strtab_shdr.sh_size);
        }

        for (auto &phdr : phdrs)
        {
            if (phdr.p_type == PT_SCE_RELA)
            {
                uint32_t reloc_off = phdr.p_offset;
                uint32_t reloc_end = phdr.p_offset + phdr.p_filesz;
                while (reloc_off < reloc_end)
                {
                    SCE_Rel reloc;
                    ifs.seekg(reloc_off, std::ios::beg);
                    ifs.read((char *)&reloc, sizeof(Elf32_Word));
                    uint32_t reloc_block_size;
                    switch (reloc.r_short & 0xf)
                    {
                    case 0:
                        reloc_block_size = 12;
                        break;
                    case 2:
                    case 3:
                        LOG(WARN, "undocumented relocation type {} found!", (int)reloc.r_short);
                        [[fallthrough]];
                    case 1:
                        reloc_block_size = 8;
                        break;
                    case 4:
                    case 5:
                    case 6:
                    case 7:
                    case 8:
                    case 9:
                        LOG(WARN, "undocumented relocation type {} found!", (int)reloc.r_short);
                        reloc_block_size = 4;
                        break;
                    default:
                        throw std::out_of_range("unexpected relocation type");
                    }

                    reloc_off += reloc_block_size;
                    ifs.read(((char *)&reloc) + sizeof(Elf32_Word), reloc_block_size - sizeof(Elf32_Word));

                    relocations.push_back(reloc);
                }
            }
        }

        assert((ehdr.e_entry >> 30) < phdrs.size());
        auto module_info_off = phdrs[ehdr.e_entry >> 30].p_offset + (ehdr.e_entry & 0x3fffffff);
        ifs.seekg(module_info_off, std::ios::beg);
        ifs.read((char *)&module_info, sizeof(sce_module_info_raw));
        if (module_info.type != 0x0 && module_info.type != 0x6)
            throw std::invalid_argument("sce_module_info is invalid");

        uint32_t off = module_info.export_top;
        while (off && off != module_info.export_end)
        {
            sce_module_exports_raw exp;
            ifs.seekg(phdrs[off >> 30].p_offset + (off & 0x3fffffff), std::ios::beg);
            ifs.read((char *)&exp, sizeof(sce_module_exports_raw));

            exports.push_back(exp);
            off += exp.size;
        }

        off = module_info.import_top;
        while (off && off != module_info.import_end)
        {
            sce_module_import_item imp;
            ifs.seekg(phdrs[off >> 30].p_offset + (off & 0x3fffffff), std::ios::beg);
            ifs.read((char *)&imp, 4);
            assert(imp.short_import.size == 0x24 || imp.long_import.size == 0x34);
            ifs.read(((char *)&imp) + 4, imp.short_import.size - 4);

            imports.push_back(imp);
            off += imp.short_import.size;
        }

        assert(ifs);
    }

    virtual ~VELF()
    {
        if (p_strtab)
        {
            delete[] p_strtab;
            p_strtab = nullptr;
        }
    }

    virtual std::pair<uint32_t, uint32_t> load_and_relocate(std::function<uint32_t(uint32_t, size_t)> mmap_func,
                                                            const MemoryAccessProxy &target) const
    {
        assert(ifs);

        auto memory_req = memory_needed_for_load_segments();
        std::unique_ptr<char[]> buffer(new char[memory_req.second]);
        uint32_t load_base = mmap_func(0, memory_req.first);

        uint32_t virt_base = -1;
        for (auto &phdr : phdrs)
        {
            switch (phdr.p_type)
            {
            case PT_LOAD:
                if (virt_base == -1)
                    virt_base = phdr.p_vaddr;

                if (phdr.p_memsz)
                {
                    ifs.seekg(phdr.p_offset, std::ios_base::beg);
                    ifs.read(buffer.get(), phdr.p_filesz);
                    memset(buffer.get() + phdr.p_filesz, 0, phdr.p_memsz - phdr.p_filesz);
                    target.copy_in(load_base + phdr.p_vaddr - virt_base, buffer.get(), phdr.p_memsz);
                }
                break;
            }
        }

        for (auto &reloc : relocations)
        {
            uint32_t P, S, A, Offset;

            uint16_t code, code2 = 0, dist2 = 0;
            switch (reloc.r_short)
            {
            case 0: // long, 12 bytes
                code = reloc.r_long_entry.r_code;
                Offset = reloc.r_long_entry.r_offset;
                A = reloc.r_long_entry.r_addend;
                P = find_seg_loadbase(reloc.r_long_entry.r_datseg, load_base) + Offset;
                S = find_seg_loadbase(reloc.r_long_entry.r_symseg, load_base);
                code2 = reloc.r_long_entry.r_code2;
                dist2 = reloc.r_long_entry.r_dist2;
                break;
            case 1: // short, 8 bytes
                code = reloc.r_short_entry.r_code;
                Offset = (reloc.r_short_entry.r_offset_hi << 12) + reloc.r_short_entry.r_offset_lo;
                A = reloc.r_short_entry.r_addend;
                P = find_seg_loadbase(reloc.r_short_entry.r_datseg, load_base) + Offset;
                S = find_seg_loadbase(reloc.r_short_entry.r_symseg, load_base);
                break;
            default:
                throw std::out_of_range("relocation type is not implemented");
            }

        _apply_reloc_again:
            switch (code)
            {
            case R_ARM_NONE:
            case R_ARM_V4BX:
                break;

            case R_ARM_ABS32:
            case R_ARM_TARGET1:
                target.w<uint32_t>(P, S + A);
                break;

            case R_ARM_REL32:
            case R_ARM_TARGET2:
                target.w<uint32_t>(P, S + A - P);
                break;

            case R_ARM_CALL:
            case R_ARM_JUMP24: {
                uint32_t insn_off;
                insn_off = target.r<uint16_t>(P) & 0xffffff;
                insn_off = S + A - P;
                target.w<uint32_t>(P, (target.r<uint16_t>(P) & 0xff000000) | (insn_off & 0xffffff));
            }
            break;

            case R_ARM_THM_PC22: // 10: R_ARM_THM_CALL
            {
                uint32_t upper, lower, insn_off;
                upper = target.r<uint16_t>(P) & 0x7ff;
                lower = target.r<uint16_t>(P + 2) & 0x7ff;
                insn_off = (upper << 11) | lower;
                target.w<uint16_t>(P, (target.r<uint16_t>(P) & (~0x7ff)) | (upper & 0x7ff));
                target.w<uint16_t>(P + 2, (target.r<uint16_t>(P + 2) & (~0x7ff)) | (lower & 0x7ff));
            }
            break;
            case R_ARM_PREL31:
                target.w<uint32_t>(P, (S - Offset + A) & 0x7fffffff | target.r<uint32_t>(P) & 0x4c4b400);
                break;
            case R_ARM_MOVW_ABS_NC:
            case R_ARM_MOVT_ABS: {
                struct
                {
                    uint32_t imm12 : 12;
                    uint32_t rd : 4;
                    uint32_t imm4 : 4;
                    uint32_t _ : 12;
                } instr;
                static_assert(sizeof(instr) == sizeof(uint32_t));
                target.copy_out(&instr, P, sizeof(instr));

                uint32_t val = S + A;
                if (code == R_ARM_MOVT_ABS)
                    val >>= 16;

                instr.imm12 = val & 0xfff;
                instr.imm4 = (val >> 12) & 0xf;
                target.copy_in(P, &instr, sizeof(instr));
            }
            break;
            case R_ARM_THM_MOVW_ABS_NC:
            case R_ARM_THM_MOVT_ABS: {
                struct
                {
                    uint32_t imm4 : 4;
                    uint32_t _ : 6;
                    uint32_t i : 1;
                    uint32_t __ : 5;

                    uint32_t imm8 : 8;
                    uint32_t rd : 4;
                    uint32_t imm3 : 3;
                    uint32_t zero : 1;
                    // imm16 = imm4:i:imm3:imm8
                } instr; // @see ARM Architecture Reference Manual Thumb-2 Supplement
                static_assert(sizeof(instr) == sizeof(uint32_t));
                target.copy_out(&instr, P, sizeof(instr));

                uint32_t val = S + A;
                if (code == R_ARM_THM_MOVT_ABS)
                    val >>= 16;

                instr.imm8 = val & 0xff;
                instr.imm3 = (val >> 8) & 0b111;
                instr.i = (val >> 11) & 1;
                instr.imm4 = (val >> 12) & 0xf;
                target.copy_in(P, &instr, sizeof(instr));
            }
            break;
            default:
                throw std::out_of_range("relocation code is not implemented");
            }

            // thanks to vita3k
            // code2 is undocumented, for a sec I thought we have to check case by case ...
            if (code2 != 0)
            {
                P += dist2 * 2;
                code = code2;
                code2 = 0;
                goto _apply_reloc_again;
            }
        }

        return {load_base, memory_req.first};
    }

    // pair<LIBRARY_NID, {<OBJECT_NID, stub_va>}>
    std::vector<std::pair<uint32_t, std::vector<std::pair<uint32_t, uint32_t>>>> get_imports() const
    {
        assert(ifs);
        std::vector<std::pair<uint32_t, std::vector<std::pair<uint32_t, uint32_t>>>> out;
        for (auto &item : imports)
        {
            std::vector<std::pair<uint32_t, uint32_t>> nids;
            uint32_t library_nid;
            std::vector<std::pair<uint32_t, std::pair<uint32_t, uint32_t>>> tables; // ct, ptr_nid, ptr_stub
            char name[256];
            if (item.short_import.size == 0x24)
            {
                const sce_module_imports_short_raw *imp = &(item.short_import);
                library_nid = imp->library_nid;
                tables.push_back(
                    std::make_pair(imp->num_syms_funcs, std::make_pair(imp->func_nid_table, imp->func_entry_table)));
                tables.push_back(
                    std::make_pair(imp->num_syms_vars, std::make_pair(imp->var_nid_table, imp->var_entry_table)));
                ifs.seekg(va2off(imp->library_name), std::ios::beg);
                ifs.get(name, 255, '\0');
            }
            else
            {
                const sce_module_imports_raw *imp = &(item.long_import);
                library_nid = imp->library_nid;
                tables.push_back(
                    std::make_pair(imp->num_syms_funcs, std::make_pair(imp->func_nid_table, imp->func_entry_table)));
                tables.push_back(
                    std::make_pair(imp->num_syms_vars, std::make_pair(imp->var_nid_table, imp->var_entry_table)));
                ifs.seekg(va2off(imp->library_name), std::ios::beg);
                ifs.get(name, 255, '\0');
            }
            LOG(TRACE, "{} NID={:#010x}", name, library_nid);

            for (auto &entry : tables)
            {
                uint32_t nid;
                uint32_t va;
                for (auto i = 0; i < entry.first; i++)
                {
                    assert(ifs);
                    ifs.seekg(va2off(entry.second.first) + i * sizeof(uint32_t), std::ios::beg);
                    ifs.read((char *)&nid, sizeof(uint32_t));
                    va = entry.second.second + i * sizeof(uint32_t);

                    nids.push_back(std::make_pair(nid, va));
                }
            }
            out.push_back(std::make_pair(library_nid, nids));
        }

        return out;
    }

    // pair<LIBRARY_NID, {<OBJECT_NID, <is_variable?, stub_offset>>}>
    std::vector<std::pair<uint32_t, std::vector<std::pair<uint32_t, std::pair<bool, uint32_t>>>>> get_exports() const
    {
        assert(ifs);
        std::vector<std::pair<uint32_t, std::vector<std::pair<uint32_t, std::pair<bool, uint32_t>>>>> out;
        for (auto &item : exports)
        {
            std::vector<std::pair<uint32_t, std::pair<bool, uint32_t>>> nids;
            uint32_t nid;
            uint32_t off;
            for (auto i = 0; i < item.num_syms_funcs + item.num_syms_vars; i++)
            {
                bool is_variable = i >= item.num_syms_funcs;
                ifs.seekg(va2off(item.nid_table) + i * sizeof(uint32_t), std::ios::beg);
                ifs.read((char *)&nid, sizeof(uint32_t));
                ifs.seekg(va2off(item.entry_table) + i * sizeof(uint32_t), std::ios::beg);
                ifs.read((char *)&off, sizeof(uint32_t));
                nids.push_back(std::make_pair(nid, std::make_pair(is_variable, off)));
            }
            out.push_back(std::make_pair(item.library_nid, nids));
        }
        return out;
    }

  public:
    virtual const char *name() const
    {
        return module_info.name;
    }

  public:
    sce_module_info_raw module_info;
    std::vector<sce_module_exports_raw> exports;
    struct sce_module_import_item
    {
        union {
            sce_module_imports_short_raw short_import; // size == 0x24
            sce_module_imports_raw long_import;        // size == 0x34
        };
    };
    std::vector<sce_module_import_item> imports;
    std::vector<SCE_Rel> relocations;
};

#endif