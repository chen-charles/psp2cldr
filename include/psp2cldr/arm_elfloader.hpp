#ifndef ARM_ELFLOADER_H
#define ARM_ELFLOADER_H

#include <elf.h>

/**
 * "ARM ELF" (https://developer.arm.com/documentation/espc0003/1-0).  
 * "ELF for the Arm ® Architecture" (https://developer.arm.com/documentation/ihi0044/h).
 */

#include <cassert>
#include <cstdint>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

#include <psp2cldr/access_proxy.hpp>
#include <psp2cldr/logger.hpp>

// Target Platform: sizeof(uintptr_t) == sizeof(uint32_t)
class ELFLoader_Base
{
public:
    ELFLoader_Base(const std::string &filename) : ELFLoader_Base(std::ifstream(filename, std::ios::binary)) {}

    ELFLoader_Base(std::ifstream &&stream) : ifs(std::move(stream))
    {
        if (ifs.fail())
            throw std::invalid_argument("the input stream has its failbit or badbit set");

        ifs.seekg(0, std::ios::beg);
        ifs.read((char *)&ehdr, sizeof(Elf32_Ehdr));

        if (std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS32 || ehdr.e_ident[EI_DATA] != ELFDATA2LSB || ehdr.e_ident[EI_VERSION] != EV_CURRENT || ehdr.e_machine != EM_ARM)
            throw std::invalid_argument("the input stream is not a valid ARM32 LSB ELF target (ehdr)");

        if (ehdr.e_shoff)
        {
            for (int sectionNo = 0; sectionNo < ehdr.e_shnum; sectionNo++)
            {
                Elf32_Shdr shdr;
                ifs.seekg(ehdr.e_shoff + sectionNo * sizeof(Elf32_Shdr), std::ios::beg);
                ifs.read((char *)&shdr, sizeof(Elf32_Shdr));
                shdrs.push_back(shdr);
            }
        }

        if (!ehdr.e_phoff)
            throw std::invalid_argument("Bad Image: e_phoff must exist");
        for (int phdr_idx = 0; phdr_idx < ehdr.e_phnum; phdr_idx++)
        {
            Elf32_Phdr phdr;
            ifs.seekg(ehdr.e_phoff + phdr_idx * sizeof(Elf32_Phdr), std::ios::beg);
            ifs.read((char *)&phdr, sizeof(Elf32_Phdr));
            phdrs.push_back(phdr);
        }
    }

    virtual ~ELFLoader_Base()
    {
        p_strtab = nullptr;

        if (ifs.is_open())
            ifs.close();
    }

    // @returns image load base
    virtual uint32_t load_and_relocate(std::function<uint32_t(uint32_t, size_t)> mmap_func, const MemoryAccessProxy &target) const = 0;

    virtual const char *name() const { return NULL; }

public:
    uintptr_t la2va(uintptr_t la, uintptr_t load_base) const
    {
        return la - load_base + find_va_base();
    }

    uintptr_t off2la(uintptr_t offset, uintptr_t load_base) const
    {
        return off2va(offset) - find_va_base() + load_base;
    }

    uintptr_t off2va(uintptr_t offset) const
    {
        for (auto i = 0; i < phdrs.size(); i++)
        {
            auto &phdr = phdrs[i];
            switch (phdr.p_type)
            {
            case PT_LOAD:
                if (offset >= phdr.p_offset && offset < phdr.p_offset + phdr.p_filesz)
                {
                    return offset - phdr.p_offset + phdr.p_vaddr;
                }
                break;
            default:;
            }
        }

        throw std::invalid_argument("the offset is not sitting inside a PT_LOAD segment");
    }

    uintptr_t va2la(uintptr_t va, uintptr_t load_base) const
    {
        return va - find_va_base() + load_base;
    }

    uintptr_t va2off(uintptr_t va) const
    {
        auto &phdr = phdrs[find_va_phdr_index(va)];
        return va - phdr.p_vaddr + phdr.p_offset;
    }

    uint32_t find_va_phdr_index(uintptr_t va) const
    {
        for (uint32_t i = 0; i < phdrs.size(); i++)
        {
            auto &phdr = phdrs[i];
            switch (phdr.p_type)
            {
            case PT_LOAD:
                if (va >= phdr.p_vaddr && va < phdr.p_vaddr + phdr.p_memsz)
                {
                    return i;
                }
                break;
            default:;
            }
        }

        throw std::invalid_argument("the va is not sitting inside a PT_LOAD segment");
    }

    uint32_t find_va_base() const
    {
        for (uint32_t i = 0; i < phdrs.size(); i++)
        {
            auto &phdr = phdrs[i];
            switch (phdr.p_type)
            {
            case PT_LOAD:
                return phdr.p_vaddr;
            default:;
            }
        }

        throw std::invalid_argument("no PT_LOAD segment is present");
    }

    uint32_t find_va_seg_loadbase(uintptr_t va, uintptr_t load_base) const
    {
        return find_seg_loadbase(find_va_phdr_index(va), load_base);
    }

    uint32_t find_seg_loadbase(uint32_t segment_index, uintptr_t load_base) const
    {
        return phdrs[segment_index].p_vaddr - find_va_base() + load_base;
    }

    uint32_t find_seg_vabase(uint32_t segment_index) const
    {
        return phdrs[segment_index].p_vaddr;
    }

    const char *getstr(Elf32_Word string_table_index) const
    {
        if (p_strtab == NULL)
            return NULL;
        return p_strtab + string_table_index;
    }

    // <total_memory_needed_for_LOAD, max (single) LOAD segment size>
    // i.e., <target mmap size, buffer size>
    virtual std::pair<uint32_t, uint32_t> memory_needed_for_load_segments() const
    {
        uint32_t min_vaddr = -1;
        uint32_t max_vaddr = 0;

        uint32_t max_sz = 0;

        for (auto &phdr : phdrs)
        {
            switch (phdr.p_type)
            {
            case PT_LOAD:
                min_vaddr = std::min<uint32_t>(align_down(phdr.p_vaddr, phdr.p_align), min_vaddr);
                max_vaddr = std::max<uint32_t>(align_up(phdr.p_vaddr + phdr.p_memsz, phdr.p_align), max_vaddr);
                max_sz = std::max<uint32_t>(phdr.p_memsz, max_sz);
                break;
            }
        }

        if (min_vaddr >= max_vaddr)
            return {0, 0}; // no loadable segment found

        return {max_vaddr - min_vaddr, max_sz};
    }

protected:
    static inline uint32_t align_down(uint32_t value, uint32_t alignment) { return value - value % alignment; }
    static inline uint32_t align_up(uint32_t value, uint32_t alignment) { return (value + alignment - 1) - (value + alignment - 1) % alignment; }

protected:
    mutable std::ifstream ifs;
    Elf32_Ehdr ehdr;
    std::vector<Elf32_Phdr> phdrs;
    std::vector<Elf32_Shdr> shdrs;

    char *p_strtab = nullptr; // string table
};

class ELF : public ELFLoader_Base
{
public:
    ELF(const std::string &filename) : ELF(std::ifstream(filename, std::ios::binary)) {}

    ELF(std::ifstream &&stream) : ELFLoader_Base(std::move(stream))
    {
        for (auto &phdr : phdrs)
        {
            // PT_ARM_ARCHEXT_ARCHv7

            if (phdr.p_type == PT_DYNAMIC)
            {
                std::vector<Elf32_Word> dt_needed;
                struct
                {
                    Elf32_Addr addr = 0;
                    Elf32_Word size;
                } STRTAB_data;
                struct
                {
                    Elf32_Addr addr = 0;
                    Elf32_Word size;
                    Elf32_Word entry_sz;
                } REL_data;
                struct
                {
                    Elf32_Addr addr = 0;
                    Elf32_Word size;
                    Elf32_Word entry_sz;
                } RELA_data;
                struct
                {
                    Elf32_Addr addr = 0;
                    Elf32_Word n_entries;
                    Elf32_Word entry_sz;
                } SYMTAB_data;
                struct
                {
                    Elf32_Addr addr;
                    Elf32_Word size;
                    Elf32_Word pltrelsz = 0;
                    Elf32_Word entry_typ; // DT_REL or DT_RELA
                    Elf32_Addr jmprel = 0;
                } PLTGOT_data;

                memset(&INIT_FINI_data, 0, sizeof(INIT_FINI_data));

                Elf32_Addr HASH_addr = 0;

                Elf32_Dyn dynamic;
                ifs.seekg(phdr.p_offset, std::ios::beg);
                do
                {
                    ifs.read((char *)&dynamic, sizeof(Elf32_Dyn));

                    switch (dynamic.d_tag)
                    {
                    case DT_STRTAB:
                        STRTAB_data.addr = dynamic.d_un.d_ptr;
                        break;
                    case DT_STRSZ: // DT_STRTABSZ
                        STRTAB_data.size = dynamic.d_un.d_val;
                        break;
                    case DT_RELA:
                        RELA_data.addr = dynamic.d_un.d_ptr;
                        break;
                    case DT_RELASZ:
                        RELA_data.size = dynamic.d_un.d_val;
                        break;
                    case DT_RELAENT:
                        RELA_data.entry_sz = dynamic.d_un.d_val;
                        break;
                    case DT_REL:
                        REL_data.addr = dynamic.d_un.d_ptr;
                        break;
                    case DT_RELSZ:
                        REL_data.size = dynamic.d_un.d_val;
                        break;
                    case DT_RELENT:
                        REL_data.entry_sz = dynamic.d_un.d_val;
                        break;
                    case DT_SYMTAB:
                        SYMTAB_data.addr = dynamic.d_un.d_ptr;
                        break;
                    case DT_SYMENT:
                        SYMTAB_data.entry_sz = dynamic.d_un.d_val;
                        break;
                    case DT_GNU_HASH:
                        break;
                    case DT_HASH:
                        HASH_addr = dynamic.d_un.d_ptr;
                        break;
                    case DT_SONAME:
                        p_soname_off = dynamic.d_un.d_val;
                        break;
                    case DT_NEEDED:
                        dt_needed.push_back(dynamic.d_un.d_val);
                        break;
                    case DT_PLTGOT:
                        PLTGOT_data.addr = dynamic.d_un.d_ptr;
                        break;
                    case DT_PLTREL:
                        PLTGOT_data.entry_typ = dynamic.d_un.d_val;
                        break;
                    case DT_PLTRELSZ:
                        PLTGOT_data.pltrelsz = dynamic.d_un.d_val;
                        break;
                    case DT_JMPREL:
                        PLTGOT_data.jmprel = dynamic.d_un.d_ptr;
                        break;
                    case DT_PREINIT_ARRAY:;
                        INIT_FINI_data.preinit_arr = dynamic.d_un.d_ptr;
                        break;
                    case DT_PREINIT_ARRAYSZ:
                        INIT_FINI_data.preinit_arr_sz = dynamic.d_un.d_val;
                        break;
                    case DT_INIT:
                        INIT_FINI_data.init = dynamic.d_un.d_ptr;
                        break;
                    case DT_INIT_ARRAY:
                        INIT_FINI_data.init_arr = dynamic.d_un.d_ptr;
                        break;
                    case DT_INIT_ARRAYSZ:
                        INIT_FINI_data.init_arr_sz = dynamic.d_un.d_val;
                        break;
                    case DT_FINI_ARRAY:
                        INIT_FINI_data.fini_arr = dynamic.d_un.d_ptr;
                        break;
                    case DT_FINI_ARRAYSZ:
                        INIT_FINI_data.fini_arr_sz = dynamic.d_un.d_val;
                        break;
                    case DT_FINI:
                        INIT_FINI_data.fini = dynamic.d_un.d_ptr;
                        break;
                    default:;
                    }

                    dynamics.push_back(dynamic);
                } while (dynamic.d_tag != DT_NULL);

                p_strtab = new char[STRTAB_data.size];
                ifs.seekg(STRTAB_data.addr, std::ios::beg);
                ifs.read(p_strtab, STRTAB_data.size);

                // required for deriving the # of entries in SYMTAB
                if (HASH_addr == 0)
                    throw std::runtime_error("must include sysv hash table, try --hash-style=sysv");
                ifs.seekg(HASH_addr + 4, std::ios::beg);
                ifs.read((char *)&(SYMTAB_data.n_entries), 4);

                ifs.seekg(SYMTAB_data.addr, std::ios::beg);
                for (auto i = 0; i < SYMTAB_data.n_entries; i++)
                {
                    Elf32_Sym Sym;
                    ifs.read((char *)&Sym, SYMTAB_data.entry_sz);
                    symbols.push_back(Sym);
                }

                for (auto &strtab_idx : dt_needed)
                {
                    needed.push_back(getstr(strtab_idx));
                }

                if (REL_data.addr != 0)
                {
                    ifs.seekg(REL_data.addr, std::ios::beg);
                    for (auto i = 0; i < REL_data.size; i += REL_data.entry_sz)
                    {
                        Elf32_Rel rel;
                        ifs.read((char *)&rel, sizeof(Elf32_Rel));
                        rel_s.push_back(rel);
                    }
                }

                if (RELA_data.addr != 0)
                {
                    ifs.seekg(RELA_data.addr, std::ios::beg);
                    for (auto i = 0; i < RELA_data.size; i += RELA_data.entry_sz)
                    {
                        Elf32_Rela rela;
                        ifs.read((char *)&rela, sizeof(Elf32_Rela));
                        rela_s.push_back(rela);
                    }
                    break;
                }

                if (PLTGOT_data.jmprel != 0)
                {
                    ifs.seekg(PLTGOT_data.jmprel, std::ios::beg);
                    if (PLTGOT_data.entry_typ == DT_REL)
                    {
                        for (auto i = 0; i < PLTGOT_data.pltrelsz / sizeof(Elf32_Rel); i++)
                        {
                            Elf32_Rel rel;
                            ifs.read((char *)&rel, sizeof(Elf32_Rel));
                            rel_s.push_back(rel);
                        }
                    }
                    else
                    {
                        for (auto i = 0; i < PLTGOT_data.pltrelsz / sizeof(Elf32_Rela); i++)
                        {
                            Elf32_Rela rela;
                            ifs.read((char *)&rela, sizeof(Elf32_Rela));
                            rela_s.push_back(rela);
                        }
                    }
                }
            }
        }

        assert(ifs);
    }

    virtual ~ELF()
    {
        if (p_strtab)
        {
            delete[] p_strtab;
            p_strtab = nullptr;
        }
    }

    virtual uint32_t load_and_relocate(std::function<uint32_t(uint32_t, size_t)> mmap_func, const MemoryAccessProxy &target) const
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
                    break;
                }
            }
        }

        for (auto &rel : rel_s)
        {
            uint32_t P = va2la(rel.r_offset, load_base);
            uint32_t B_S = find_va_seg_loadbase(rel.r_offset, load_base);

            // implicit handle of STN_UNDEF==0
            apply_relocation(target, ELF32_R_TYPE(rel.r_info), P, symbols[ELF32_R_SYM(rel.r_info)], 0, B_S, false, load_base);
        }

        for (auto &rela : rela_s)
        {
            uint32_t P = va2la(rela.r_offset, load_base);
            uint32_t B_S = find_va_seg_loadbase(rela.r_offset, load_base);

            // implicit handle of STN_UNDEF==0
            apply_relocation(target, ELF32_R_TYPE(rela.r_info), P, symbols[ELF32_R_SYM(rela.r_info)], rela.r_addend, B_S, true, load_base);
        }

        return load_base;
    }

    std::vector<uintptr_t> get_init_routines(const MemoryAccessProxy &target, uintptr_t load_base) const // returning LAs
    {
        std::vector<uintptr_t> init_routines;

        if (INIT_FINI_data.preinit_arr != 0)
        {
            for (auto i = 0; i < INIT_FINI_data.preinit_arr_sz / sizeof(uint32_t); i++)
            {
                init_routines.push_back(target.r<uint32_t>(va2la(INIT_FINI_data.preinit_arr, load_base) + i * sizeof(uint32_t)));
                init_routines.back() = va2la(init_routines.back(), load_base);
            }
        }

        if (INIT_FINI_data.init != 0)
            init_routines.push_back(va2la(INIT_FINI_data.init, load_base));

        if (INIT_FINI_data.init_arr != 0)
        {
            for (auto i = 0; i < INIT_FINI_data.init_arr_sz / sizeof(uint32_t); i++)
            {
                init_routines.push_back(target.r<uint32_t>(va2la(INIT_FINI_data.init_arr, load_base) + i * sizeof(uint32_t)));
            }
        }

        return init_routines;
    }

    std::vector<uintptr_t> get_term_routines(const MemoryAccessProxy &target, uintptr_t load_base) const // returning LAs
    {
        std::vector<uintptr_t> term_routines;

        if (INIT_FINI_data.fini_arr != 0)
        {
            for (auto i = 0; i < INIT_FINI_data.fini_arr_sz / sizeof(uint32_t); i++)
            {
                term_routines.push_back(target.r<uint32_t>(va2la(INIT_FINI_data.fini_arr, load_base) + i * sizeof(uint32_t)));
                term_routines.back() = va2la(term_routines.back(), load_base);
            }
        }

        if (INIT_FINI_data.fini != 0)
            term_routines.push_back(va2la(INIT_FINI_data.fini, load_base));

        return term_routines;
    }

    // pair<Elf32_Sym, stub_va>
    std::vector<std::pair<Elf32_Sym, uint32_t>> get_imports() const
    {
        std::vector<std::pair<Elf32_Sym, uint32_t>> out;
        for (auto &rel : rel_s)
        {
            if (ELF32_R_SYM(rel.r_info) != 0)
            {
                auto Sym = symbols[ELF32_R_SYM(rel.r_info)];

                switch (Sym.st_shndx)
                {
                case SHN_UNDEF:
                    out.push_back(std::make_pair(Sym, rel.r_offset));
                    break;
                }
            }
        }

        for (auto &rela : rela_s)
        {
            if (ELF32_R_SYM(rela.r_info) != 0)
            {
                auto Sym = symbols[ELF32_R_SYM(rela.r_info)];

                switch (Sym.st_shndx)
                {
                case SHN_UNDEF:
                    out.push_back(std::make_pair(Sym, rela.r_offset));
                    break;
                }
            }
        }

        return out;
    }

    const std::vector<const char *> &get_import_libraries() const
    {
        return needed;
    }

    // pair<sym, stub_va>
    std::vector<std::pair<Elf32_Sym, uint32_t>> get_exports() const
    {
        std::vector<std::pair<Elf32_Sym, uint32_t>> out;
        for (auto &Sym : symbols)
        {
            switch (Sym.st_shndx)
            {
            case SHN_COMMON:
                throw;
            case SHN_UNDEF:
                break;
            case SHN_ABS:
                [[fallthrough]];
            default:
                if (
                    (ELF32_ST_BIND(Sym.st_info) == STB_GLOBAL || ELF32_ST_BIND(Sym.st_info) == STB_WEAK) &&
                    (ELF32_ST_VISIBILITY(Sym.st_other) == STV_DEFAULT || ELF32_ST_VISIBILITY(Sym.st_other) == STV_PROTECTED))
                    out.push_back(std::make_pair(Sym, Sym.st_value));
                break;
            }
        }
        return out;
    }

public:
    virtual const char *name() const
    {
        if (p_soname_off == -1)
            return NULL;
        return getstr(p_soname_off);
    }

protected:
    std::vector<Elf32_Sym> symbols;

    std::vector<Elf32_Rela> rela_s;
    std::vector<Elf32_Rel> rel_s;

    std::vector<Elf32_Dyn> dynamics;

    std::vector<const char *> needed;

    // must be resolved after reloc
    struct
    {
        Elf32_Addr preinit_arr;
        Elf32_Word preinit_arr_sz;
        Elf32_Addr init;
        Elf32_Addr init_arr;
        Elf32_Word init_arr_sz;

        Elf32_Addr fini_arr;
        Elf32_Word fini_arr_sz;
        Elf32_Addr fini;
    } INIT_FINI_data;

    Elf32_Word p_soname_off = -1;

protected:
    virtual void apply_relocation(const MemoryAccessProxy &target, uint32_t code, uint32_t P, const Elf32_Sym &Sym, uint32_t A, uint32_t B_S, bool is_RelA, uintptr_t load_base) const
    {
        uint32_t Pa = P & 0xFFFFFFFC;
        uint32_t S = 0;

        if (code != R_ARM_RELATIVE)
            switch (Sym.st_shndx)
            {
            case SHN_COMMON:
                throw;
            case SHN_UNDEF: // handled at import time
                return;
            case SHN_ABS:
                S = Sym.st_value;
                break;
            default:
                S = va2la(Sym.st_value, load_base);
            }

        // "T is 1 if the target symbol S has type STT_FUNC and the symbol addresses a Thumb instruction; it is 0 otherwise."
        uint32_t T = 0;
        if (ELF32_ST_TYPE(Sym.st_info) == STT_FUNC && S % 2 == 1)
            T = 1;

        // the addend
        A = (is_RelA ? A : target.r<uint32_t>(P));

        switch (code)
        {
        case R_ARM_NONE:
        case R_ARM_V4BX:
            break;

        case R_ARM_REL32:
            target.w<uint32_t>(P, ((S + A) | T) | (-P));
            break;
        case R_ARM_ABS32:
            target.w<uint32_t>(P, (S + A) | T);
            break;

        case R_ARM_GLOB_DAT:
        case R_ARM_JUMP_SLOT:
            target.w<uint32_t>(P, S | T);
            break;

        case R_ARM_RELATIVE:
            if (Sym.st_shndx == SHN_UNDEF)
                target.w<uint32_t>(P, A + load_base);
            else
                target.w<uint32_t>(P, A + B_S);
            break;
        default:
            throw std::out_of_range("relocation code is not implemented");
        }
    }
};

#endif
