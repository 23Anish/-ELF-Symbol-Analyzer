#include "reporter.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <map>

Reporter::Reporter(const ElfParser& parser, const Options& opts)
    : parser_(parser), opts_(opts) {}

void Reporter::report() const {
    if (opts_.json_output) report_json();
    else                   report_text();
}

// ── Text output ──────────────────────────────────────────────────────────────

void Reporter::report_text() const {
    const auto& info = parser_.info();

    std::cout << "File: " << parser_.path() << "\n";
    std::cout << "Type: " << etype_str(info.e_type)
              << "  Arch: " << machine_str(info.e_machine)
              << "  Class: " << (info.is_64bit ? "ELF64" : "ELF32")
              << "  Endian: " << (info.is_little_endian ? "LE" : "BE") << "\n";
    if (info.e_entry)
        std::cout << "Entry: 0x" << std::hex << info.e_entry << std::dec << "\n";
    std::cout << "\n";

    if (opts_.show_sections) {
        print_sections();
        std::cout << "\n";
    }
    if (opts_.show_deps) {
        print_deps();
        std::cout << "\n";
    }
    if (opts_.show_undefined) {
        print_undefined();
        std::cout << "\n";
    }
    if (opts_.show_weak) {
        print_weak();
        std::cout << "\n";
    }
    if (opts_.show_symbols) {
        if (!info.symbols.empty()) {
            std::cout << "── Static Symbol Table (.symtab) ──\n";
            print_symbols(false);
            std::cout << "\n";
        }
        if (!info.dyn_symbols.empty()) {
            std::cout << "── Dynamic Symbol Table (.dynsym) ──\n";
            print_symbols(true);
        }
    }
}

void Reporter::print_sections() const {
    const auto& secs = parser_.info().sections;
    if (secs.empty()) { std::cout << "No sections found.\n"; return; }

    // sort by size descending
    std::vector<Section> sorted = secs;
    std::sort(sorted.begin(), sorted.end(),
              [](const Section& a, const Section& b){ return a.size > b.size; });

    std::cout << "── Sections (by size) ──\n";
    std::cout << std::left
              << std::setw(24) << "Name"
              << std::setw(10) << "Size"
              << std::setw(18) << "Address"
              << "Type\n";
    std::cout << std::string(64, '-') << "\n";
    for (const auto& s : sorted) {
        if (s.name.empty() && s.size == 0) continue;
        std::cout << std::left
                  << std::setw(24) << (s.name.empty() ? "<unnamed>" : s.name)
                  << std::setw(10) << human_size(s.size)
                  << "0x" << std::hex << std::setw(16) << s.addr << std::dec
                  << s.type << "\n";
    }
}

void Reporter::print_symbols(bool dynamic) const {
    const auto& syms = dynamic ? parser_.info().dyn_symbols : parser_.info().symbols;
    if (syms.empty()) { std::cout << "  (none)\n"; return; }

    std::cout << std::left
              << std::setw(20) << "Bind"
              << std::setw(12) << "Type"
              << std::setw(10) << "Size"
              << std::setw(18) << "Value"
              << "Name\n";
    std::cout << std::string(78, '-') << "\n";

    for (const auto& sym : syms) {
        if (sym.name.empty()) continue;
        std::cout << std::left
                  << std::setw(20) << bind_str(sym.bind)
                  << std::setw(12) << type_str(sym.type)
                  << std::setw(10) << human_size(sym.size)
                  << "0x" << std::hex << std::setw(16) << sym.value << std::dec
                  << sym.name << "\n";
    }
    std::cout << "  Total: " << syms.size() << " symbols\n";
}

void Reporter::print_undefined() const {
    const auto& info = parser_.info();
    std::vector<const Symbol*> undef;
    for (const auto& s : info.symbols)     if (s.is_undefined() && !s.name.empty()) undef.push_back(&s);
    for (const auto& s : info.dyn_symbols) if (s.is_undefined() && !s.name.empty()) undef.push_back(&s);

    std::cout << "── Undefined Symbols (" << undef.size() << ") ──\n";
    if (undef.empty()) { std::cout << "  (none)\n"; return; }
    for (const auto* s : undef)
        std::cout << "  [" << type_str(s->type) << "] " << s->name << "\n";
}

void Reporter::print_weak() const {
    const auto& info = parser_.info();
    std::vector<const Symbol*> weak;
    for (const auto& s : info.symbols)     if (s.is_weak() && !s.name.empty()) weak.push_back(&s);
    for (const auto& s : info.dyn_symbols) if (s.is_weak() && !s.name.empty()) weak.push_back(&s);

    std::cout << "── Weak Symbols (" << weak.size() << ") ──\n";
    if (weak.empty()) { std::cout << "  (none)\n"; return; }
    for (const auto* s : weak)
        std::cout << "  [" << type_str(s->type) << "] "
                  << s->name
                  << (s->is_undefined() ? "  <undefined>" : "") << "\n";
}

void Reporter::print_deps() const {
    const auto& libs = parser_.info().needed_libs;
    std::cout << "── Shared Library Dependencies (" << libs.size() << ") ──\n";
    if (libs.empty()) { std::cout << "  (none — may be statically linked)\n"; return; }
    for (const auto& l : libs)
        std::cout << "  " << l << "\n";
}

// ── JSON output ──────────────────────────────────────────────────────────────

void Reporter::report_json() const {
    const auto& info = parser_.info();
    std::cout << "{\n";
    std::cout << "  \"file\": \"" << json_escape(parser_.path()) << "\",\n";
    std::cout << "  \"type\": \"" << etype_str(info.e_type) << "\",\n";
    std::cout << "  \"arch\": \"" << machine_str(info.e_machine) << "\",\n";
    std::cout << "  \"class\": \"" << (info.is_64bit ? "ELF64" : "ELF32") << "\",\n";
    std::cout << "  \"endian\": \"" << (info.is_little_endian ? "LE" : "BE") << "\",\n";
    std::cout << "  \"entry\": \"0x" << std::hex << info.e_entry << std::dec << "\",\n";

    // sections
    std::cout << "  \"sections\": [\n";
    bool first = true;
    for (const auto& s : info.sections) {
        if (s.name.empty() && s.size == 0) continue;
        if (!first) std::cout << ",\n";
        first = false;
        std::cout << "    {\"name\":\"" << json_escape(s.name)
                  << "\",\"size\":" << s.size
                  << ",\"addr\":\"0x" << std::hex << s.addr << std::dec << "\"}";
    }
    std::cout << "\n  ],\n";

    // deps
    std::cout << "  \"dependencies\": [";
    for (size_t i = 0; i < info.needed_libs.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << "\"" << json_escape(info.needed_libs[i]) << "\"";
    }
    std::cout << "],\n";

    // undefined
    std::cout << "  \"undefined_symbols\": [\n";
    first = true;
    auto emit_sym = [&](const Symbol& s, bool is_undef_filter) {
        if (is_undef_filter && !s.is_undefined()) return;
        if (s.name.empty()) return;
        if (!first) std::cout << ",\n";
        first = false;
        std::cout << "    {\"name\":\"" << json_escape(s.name)
                  << "\",\"bind\":\"" << bind_str(s.bind)
                  << "\",\"type\":\"" << type_str(s.type)
                  << "\",\"value\":\"0x" << std::hex << s.value << std::dec
                  << "\",\"size\":" << s.size << "}";
    };
    for (const auto& s : info.symbols)     emit_sym(s, true);
    for (const auto& s : info.dyn_symbols) emit_sym(s, true);
    std::cout << "\n  ],\n";

    // all symbols
    std::cout << "  \"symbols\": [\n";
    first = true;
    for (const auto& s : info.symbols)     emit_sym(s, false);
    for (const auto& s : info.dyn_symbols) emit_sym(s, false);
    std::cout << "\n  ]\n}\n";
}

// ── Helpers ──────────────────────────────────────────────────────────────────

std::string Reporter::bind_str(SymbolBind b) {
    switch (b) {
        case SymbolBind::Local:  return "LOCAL";
        case SymbolBind::Global: return "GLOBAL";
        case SymbolBind::Weak:   return "WEAK";
        default:                 return "OTHER";
    }
}
std::string Reporter::type_str(SymbolType t) {
    switch (t) {
        case SymbolType::Object:  return "OBJECT";
        case SymbolType::Func:    return "FUNC";
        case SymbolType::Section: return "SECTION";
        case SymbolType::File:    return "FILE";
        default:                  return "NOTYPE";
    }
}
std::string Reporter::vis_str(SymbolVis v) {
    switch (v) {
        case SymbolVis::Internal:  return "INTERNAL";
        case SymbolVis::Hidden:    return "HIDDEN";
        case SymbolVis::Protected: return "PROTECTED";
        default:                   return "DEFAULT";
    }
}
std::string Reporter::etype_str(uint16_t e) {
    switch (e) {
        case 1: return "REL (relocatable)";
        case 2: return "EXEC (executable)";
        case 3: return "DYN (shared object)";
        case 4: return "CORE";
        default: return "UNKNOWN";
    }
}
std::string Reporter::machine_str(uint16_t m) {
    switch (m) {
        case 3:   return "x86";
        case 40:  return "ARM";
        case 62:  return "x86-64";
        case 183: return "AArch64";
        case 243: return "RISC-V";
        case 20:  return "PowerPC";
        case 21:  return "PowerPC64";
        case 8:   return "MIPS";
        default:  return "ARCH(" + std::to_string(m) + ")";
    }
}
std::string Reporter::human_size(uint64_t sz) {
    if (sz == 0) return "0";
    if (sz < 1024) return std::to_string(sz) + "B";
    if (sz < 1024*1024) return std::to_string(sz/1024) + "KB";
    return std::to_string(sz/(1024*1024)) + "MB";
}
std::string Reporter::json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else           out += c;
    }
    return out;
}