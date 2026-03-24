#include "elf_parser.h"

#include <fstream>
#include <cstring>
#include <iostream>
#include <stdexcept>

// ELF magic & identity offsets
#define EI_MAG0       0
#define EI_CLASS      4
#define EI_DATA       5
#define EI_NIDENT     16
#define ELFMAG        "\177ELF"
#define ELFCLASS32    1
#define ELFCLASS64    2
#define ELFDATA2LSB   1
#define ELFDATA2MSB   2

// e_type
#define ET_REL  1
#define ET_EXEC 2
#define ET_DYN  3

// section types
#define SHT_SYMTAB   2
#define SHT_STRTAB   3
#define SHT_DYNAMIC  6
#define SHT_DYNSYM   11

// symbol bind/type
#define STB_LOCAL   0
#define STB_GLOBAL  1
#define STB_WEAK    2
#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4
#define STV_DEFAULT   0
#define STV_INTERNAL  1
#define STV_HIDDEN    2
#define STV_PROTECTED 3

// dynamic tags
#define DT_NULL   0
#define DT_NEEDED 1

// ELF32 structs
struct Elf32_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version, e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum;
    uint16_t e_shentsize, e_shnum, e_shstrndx;
};
struct Elf32_Shdr {
    uint32_t sh_name, sh_type, sh_flags, sh_addr;
    uint32_t sh_offset, sh_size, sh_link, sh_info;
    uint32_t sh_addralign, sh_entsize;
};
struct Elf32_Sym {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t  st_info, st_other;
    uint16_t st_shndx;
};
struct Elf32_Dyn { uint32_t d_tag; uint32_t d_val; };

// ELF64 structs
struct Elf64_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum;
    uint16_t e_shentsize, e_shnum, e_shstrndx;
};
struct Elf64_Shdr {
    uint32_t sh_name, sh_type;
    uint64_t sh_flags, sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info;
    uint64_t sh_addralign, sh_entsize;
};
struct Elf64_Sym {
    uint32_t st_name;
    uint8_t  st_info, st_other;
    uint16_t st_shndx;
    uint64_t st_value, st_size;
};
struct Elf64_Dyn { uint64_t d_tag; uint64_t d_val; };

ElfParser::ElfParser(const std::string& path) : path_(path) {}

bool ElfParser::load() {
    std::ifstream f(path_, std::ios::binary | std::ios::ate);
    if (!f) { std::cerr << "Cannot open file: " << path_ << "\n"; return false; }
    auto sz = f.tellg();
    if (sz < 16) { std::cerr << "File too small\n"; return false; }
    data_.resize(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(data_.data()), sz);
    if (!f) { std::cerr << "Read error\n"; return false; }
    return parse();
}

bool ElfParser::parse() {
    if (data_.size() < 16) return false;
    if (memcmp(data_.data(), ELFMAG, 4) != 0) {
        std::cerr << "Not an ELF file\n"; return false;
    }
    info_.is_64bit         = (data_[EI_CLASS] == ELFCLASS64);
    info_.is_little_endian = (data_[EI_DATA]  == ELFDATA2LSB);

    return info_.is_64bit ? parse64() : parse32();
}

uint16_t ElfParser::read_u16(const uint8_t* p) const {
    if (info_.is_little_endian)
        return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}
uint32_t ElfParser::read_u32(const uint8_t* p) const {
    if (info_.is_little_endian)
        return p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
    return (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
}
uint64_t ElfParser::read_u64(const uint8_t* p) const {
    if (info_.is_little_endian) {
        uint64_t v = 0;
        for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
        return v;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

static SymbolBind bind_from(uint8_t info) {
    switch (info >> 4) {
        case STB_LOCAL:  return SymbolBind::Local;
        case STB_GLOBAL: return SymbolBind::Global;
        case STB_WEAK:   return SymbolBind::Weak;
        default:         return SymbolBind::Other;
    }
}
static SymbolType type_from(uint8_t info) {
    switch (info & 0xf) {
        case STT_OBJECT:  return SymbolType::Object;
        case STT_FUNC:    return SymbolType::Func;
        case STT_SECTION: return SymbolType::Section;
        case STT_FILE:    return SymbolType::File;
        default:          return SymbolType::NoType;
    }
}
static SymbolVis vis_from(uint8_t other) {
    switch (other & 0x3) {
        case STV_INTERNAL:  return SymbolVis::Internal;
        case STV_HIDDEN:    return SymbolVis::Hidden;
        case STV_PROTECTED: return SymbolVis::Protected;
        default:            return SymbolVis::Default;
    }
}

bool ElfParser::parse32() {
    const uint8_t* d = data_.data();
    if (data_.size() < sizeof(Elf32_Ehdr)) return false;
    Elf32_Ehdr eh;
    memcpy(&eh, d, sizeof(eh));

    info_.e_type    = read_u16(reinterpret_cast<uint8_t*>(&eh.e_type));
    info_.e_machine = read_u16(reinterpret_cast<uint8_t*>(&eh.e_machine));
    info_.e_entry   = read_u32(reinterpret_cast<uint8_t*>(&eh.e_entry));

    uint32_t shoff     = read_u32(reinterpret_cast<uint8_t*>(&eh.e_shoff));
    uint16_t shnum     = read_u16(reinterpret_cast<uint8_t*>(&eh.e_shnum));
    uint16_t shentsize = read_u16(reinterpret_cast<uint8_t*>(&eh.e_shentsize));
    uint16_t shstrndx  = read_u16(reinterpret_cast<uint8_t*>(&eh.e_shstrndx));

    if (shoff == 0 || shnum == 0) return true;
    if (shoff + shnum * shentsize > data_.size()) return false;

    // section name string table
    uint32_t shstr_off = read_u32(d + shoff + shstrndx * shentsize + offsetof(Elf32_Shdr, sh_offset));
    uint32_t shstr_sz  = read_u32(d + shoff + shstrndx * shentsize + offsetof(Elf32_Shdr, sh_size));
    const char* shstr  = reinterpret_cast<const char*>(d + shstr_off);

    // parse sections
    for (uint16_t i = 0; i < shnum; ++i) {
        const uint8_t* shp = d + shoff + i * shentsize;
        Section sec;
        uint32_t name_off = read_u32(shp + offsetof(Elf32_Shdr, sh_name));
        if (name_off < shstr_sz) sec.name = shstr + name_off;
        sec.type   = read_u32(shp + offsetof(Elf32_Shdr, sh_type));
        sec.offset = read_u32(shp + offsetof(Elf32_Shdr, sh_offset));
        sec.size   = read_u32(shp + offsetof(Elf32_Shdr, sh_size));
        sec.addr   = read_u32(shp + offsetof(Elf32_Shdr, sh_addr));
        sec.align  = read_u32(shp + offsetof(Elf32_Shdr, sh_addralign));
        sec.flags  = read_u32(shp + offsetof(Elf32_Shdr, sh_flags));
        info_.sections.push_back(sec);
    }

    // parse symbol tables and dynamic section
    for (const auto& sec : info_.sections) {
        if (sec.type != SHT_SYMTAB && sec.type != SHT_DYNSYM && sec.type != SHT_DYNAMIC) continue;
        if (sec.offset + sec.size > data_.size()) continue;

        if (sec.type == SHT_DYNAMIC) {
            // find dynstr section
            std::string dynstr_data;
            for (const auto& s2 : info_.sections) {
                if (s2.name == ".dynstr" && s2.offset + s2.size <= data_.size()) {
                    dynstr_data.assign(reinterpret_cast<const char*>(d + s2.offset), s2.size);
                    break;
                }
            }
            size_t n = sec.size / sizeof(Elf32_Dyn);
            for (size_t j = 0; j < n; ++j) {
                const uint8_t* dp = d + sec.offset + j * sizeof(Elf32_Dyn);
                uint32_t tag = read_u32(dp);
                uint32_t val = read_u32(dp + 4);
                if (tag == DT_NULL) break;
                if (tag == DT_NEEDED && val < dynstr_data.size())
                    info_.needed_libs.push_back(dynstr_data.c_str() + val);
            }
            continue;
        }

        // find associated string table
        // link field holds strtab section index
        uint16_t sec_idx = 0;
        for (uint16_t k = 0; k < shnum; ++k) {
            if (info_.sections[k].name == sec.name) { sec_idx = k; break; }
        }
        uint32_t link = read_u32(d + shoff + sec_idx * shentsize + offsetof(Elf32_Shdr, sh_link));
        if (link >= shnum) continue;
        const Section& strsec = info_.sections[link];
        if (strsec.offset + strsec.size > data_.size()) continue;
        const char* strtab = reinterpret_cast<const char*>(d + strsec.offset);

        bool is_dyn = (sec.type == SHT_DYNSYM);
        size_t n = sec.size / sizeof(Elf32_Sym);
        for (size_t j = 0; j < n; ++j) {
            const uint8_t* sp = d + sec.offset + j * sizeof(Elf32_Sym);
            Symbol sym;
            uint32_t name_off = read_u32(sp + offsetof(Elf32_Sym, st_name));
            sym.name    = (name_off < strsec.size) ? strtab + name_off : "";
            sym.value   = read_u32(sp + offsetof(Elf32_Sym, st_value));
            sym.size    = read_u32(sp + offsetof(Elf32_Sym, st_size));
            sym.bind    = bind_from(d[sec.offset + j * sizeof(Elf32_Sym) + offsetof(Elf32_Sym, st_info)]);
            sym.type    = type_from(d[sec.offset + j * sizeof(Elf32_Sym) + offsetof(Elf32_Sym, st_info)]);
            sym.vis     = vis_from(d[sec.offset + j * sizeof(Elf32_Sym) + offsetof(Elf32_Sym, st_other)]);
            sym.shndx   = read_u16(sp + offsetof(Elf32_Sym, st_shndx));
            sym.is_dynamic = is_dyn;
            if (is_dyn) info_.dyn_symbols.push_back(sym);
            else        info_.symbols.push_back(sym);
        }
    }
    return true;
}

bool ElfParser::parse64() {
    const uint8_t* d = data_.data();
    if (data_.size() < sizeof(Elf64_Ehdr)) return false;
    Elf64_Ehdr eh;
    memcpy(&eh, d, sizeof(eh));

    info_.e_type    = read_u16(reinterpret_cast<uint8_t*>(&eh.e_type));
    info_.e_machine = read_u16(reinterpret_cast<uint8_t*>(&eh.e_machine));
    info_.e_entry   = read_u64(reinterpret_cast<uint8_t*>(&eh.e_entry));

    uint64_t shoff     = read_u64(reinterpret_cast<uint8_t*>(&eh.e_shoff));
    uint16_t shnum     = read_u16(reinterpret_cast<uint8_t*>(&eh.e_shnum));
    uint16_t shentsize = read_u16(reinterpret_cast<uint8_t*>(&eh.e_shentsize));
    uint16_t shstrndx  = read_u16(reinterpret_cast<uint8_t*>(&eh.e_shstrndx));

    if (shoff == 0 || shnum == 0) return true;
    if (shoff + (uint64_t)shnum * shentsize > data_.size()) return false;

    uint64_t shstr_off = read_u64(d + shoff + shstrndx * shentsize + offsetof(Elf64_Shdr, sh_offset));
    uint64_t shstr_sz  = read_u64(d + shoff + shstrndx * shentsize + offsetof(Elf64_Shdr, sh_size));
    const char* shstr  = reinterpret_cast<const char*>(d + shstr_off);

    for (uint16_t i = 0; i < shnum; ++i) {
        const uint8_t* shp = d + shoff + i * shentsize;
        Section sec;
        uint32_t name_off = read_u32(shp + offsetof(Elf64_Shdr, sh_name));
        if (name_off < shstr_sz) sec.name = shstr + name_off;
        sec.type   = read_u32(shp + offsetof(Elf64_Shdr, sh_type));
        sec.offset = read_u64(shp + offsetof(Elf64_Shdr, sh_offset));
        sec.size   = read_u64(shp + offsetof(Elf64_Shdr, sh_size));
        sec.addr   = read_u64(shp + offsetof(Elf64_Shdr, sh_addr));
        sec.align  = read_u64(shp + offsetof(Elf64_Shdr, sh_addralign));
        sec.flags  = static_cast<uint32_t>(read_u64(shp + offsetof(Elf64_Shdr, sh_flags)));
        info_.sections.push_back(sec);
    }

    for (uint16_t i = 0; i < shnum; ++i) {
        const Section& sec = info_.sections[i];
        if (sec.type != SHT_SYMTAB && sec.type != SHT_DYNSYM && sec.type != SHT_DYNAMIC) continue;
        if (sec.offset + sec.size > data_.size()) continue;

        if (sec.type == SHT_DYNAMIC) {
            std::string dynstr_data;
            for (const auto& s2 : info_.sections) {
                if (s2.name == ".dynstr" && s2.offset + s2.size <= data_.size()) {
                    dynstr_data.assign(reinterpret_cast<const char*>(d + s2.offset), s2.size);
                    break;
                }
            }
            size_t n = sec.size / sizeof(Elf64_Dyn);
            for (size_t j = 0; j < n; ++j) {
                const uint8_t* dp = d + sec.offset + j * sizeof(Elf64_Dyn);
                uint64_t tag = read_u64(dp);
                uint64_t val = read_u64(dp + 8);
                if (tag == DT_NULL) break;
                if (tag == DT_NEEDED && val < dynstr_data.size())
                    info_.needed_libs.push_back(dynstr_data.c_str() + val);
            }
            continue;
        }

        uint32_t link = read_u32(d + shoff + i * shentsize + offsetof(Elf64_Shdr, sh_link));
        if (link >= shnum) continue;
        const Section& strsec = info_.sections[link];
        if (strsec.offset + strsec.size > data_.size()) continue;
        const char* strtab = reinterpret_cast<const char*>(d + strsec.offset);

        bool is_dyn = (sec.type == SHT_DYNSYM);
        size_t n = sec.size / sizeof(Elf64_Sym);
        for (size_t j = 0; j < n; ++j) {
            const uint8_t* sp = d + sec.offset + j * sizeof(Elf64_Sym);
            Symbol sym;
            uint32_t name_off = read_u32(sp + offsetof(Elf64_Sym, st_name));
            sym.name  = (name_off < strsec.size) ? strtab + name_off : "";
            sym.bind  = bind_from(d[sec.offset + j * sizeof(Elf64_Sym) + offsetof(Elf64_Sym, st_info)]);
            sym.type  = type_from(d[sec.offset + j * sizeof(Elf64_Sym) + offsetof(Elf64_Sym, st_info)]);
            sym.vis   = vis_from(d[sec.offset + j * sizeof(Elf64_Sym) + offsetof(Elf64_Sym, st_other)]);
            sym.shndx = read_u16(sp + offsetof(Elf64_Sym, st_shndx));
            sym.value = read_u64(sp + offsetof(Elf64_Sym, st_value));
            sym.size  = read_u64(sp + offsetof(Elf64_Sym, st_size));
            sym.is_dynamic = is_dyn;
            if (is_dyn) info_.dyn_symbols.push_back(sym);
            else        info_.symbols.push_back(sym);
        }
    }
    return true;
}