#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct Options {
    bool show_symbols   = false;
    bool show_sections  = false;
    bool show_undefined = false;
    bool show_weak      = false;
    bool show_deps      = false;
    bool json_output    = false;
};

enum class SymbolBind : uint8_t {
    Local  = 0,
    Global = 1,
    Weak   = 2,
    Other
};

enum class SymbolType : uint8_t {
    NoType  = 0,
    Object  = 1,
    Func    = 2,
    Section = 3,
    File    = 4,
    Other
};

enum class SymbolVis : uint8_t {
    Default   = 0,
    Internal  = 1,
    Hidden    = 2,
    Protected = 3
};

struct Symbol {
    std::string  name;
    uint64_t     value  = 0;
    uint64_t     size   = 0;
    SymbolBind   bind   = SymbolBind::Local;
    SymbolType   type   = SymbolType::NoType;
    SymbolVis    vis    = SymbolVis::Default;
    uint16_t     shndx  = 0;      // section index (0 = UND, 0xfff1 = ABS, etc.)
    bool         is_dynamic = false;

    bool is_undefined() const { return shndx == 0; }
    bool is_weak()      const { return bind == SymbolBind::Weak; }
};

struct Section {
    std::string name;
    uint32_t    type   = 0;
    uint64_t    offset = 0;
    uint64_t    size   = 0;
    uint64_t    addr   = 0;
    uint64_t    align  = 0;
    uint32_t    flags  = 0;
};

struct ElfInfo {
    bool        is_64bit     = false;
    bool        is_little_endian = true;
    uint16_t    e_type       = 0;   // ET_EXEC, ET_DYN, ET_REL, ...
    uint16_t    e_machine    = 0;
    uint64_t    e_entry      = 0;

    std::vector<Symbol>      symbols;
    std::vector<Symbol>      dyn_symbols;
    std::vector<Section>     sections;
    std::vector<std::string> needed_libs;  // DT_NEEDED entries
};

class ElfParser {
public:
    explicit ElfParser(const std::string& path);

    bool load();
    const ElfInfo& info() const { return info_; }
    const std::string& path() const { return path_; }

private:
    std::string        path_;
    std::vector<uint8_t> data_;
    ElfInfo            info_;

    bool parse();
    bool parse32();
    bool parse64();

    template<typename Ehdr, typename Shdr, typename Sym>
    bool parse_impl();

    uint16_t read_u16(const uint8_t* p) const;
    uint32_t read_u32(const uint8_t* p) const;
    uint64_t read_u64(const uint8_t* p) const;
};