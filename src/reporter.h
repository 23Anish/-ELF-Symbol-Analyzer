#pragma once
#include "elf_parser.h"
#include <string>

class Reporter {
public:
    Reporter(const ElfParser& parser, const Options& opts);
    void report() const;

private:
    const ElfParser& parser_;
    const Options&   opts_;

    void report_text() const;
    void report_json() const;

    void print_header_info() const;
    void print_sections()    const;
    void print_symbols(bool dynamic) const;
    void print_undefined()   const;
    void print_weak()        const;
    void print_deps()        const;

    static std::string bind_str(SymbolBind b);
    static std::string type_str(SymbolType t);
    static std::string vis_str(SymbolVis  v);
    static std::string etype_str(uint16_t e);
    static std::string machine_str(uint16_t m);
    static std::string human_size(uint64_t sz);
    static std::string json_escape(const std::string& s);
};