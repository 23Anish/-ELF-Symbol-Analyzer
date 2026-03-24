#include <bits/stdc++.h>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <sstream>

#include "elf_parser.h"
#include "reporter.h"

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options] <elf-binary>\n"
              << "Options:\n"
              << "  -s, --symbols       Show symbol table (default)\n"
              << "  -S, --sections      Show section sizes\n"
              << "  -u, --undefined     Show undefined symbols only\n"
              << "  -w, --weak          Show weak symbols only\n"
              << "  -d, --deps          Show shared library dependencies\n"
              << "  -a, --all           Show everything\n"
              << "  -j, --json          Output as JSON\n"
              << "  -h, --help          Show this help\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    Options opts;
    std::string filepath;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") { print_usage(argv[0]); return 0; }
        else if (arg == "-s" || arg == "--symbols")   opts.show_symbols   = true;
        else if (arg == "-S" || arg == "--sections")  opts.show_sections  = true;
        else if (arg == "-u" || arg == "--undefined") opts.show_undefined = true;
        else if (arg == "-w" || arg == "--weak")      opts.show_weak      = true;
        else if (arg == "-d" || arg == "--deps")      opts.show_deps      = true;
        else if (arg == "-a" || arg == "--all") {
            opts.show_symbols = opts.show_sections = opts.show_undefined =
            opts.show_weak = opts.show_deps = true;
        }
        else if (arg == "-j" || arg == "--json") opts.json_output = true;
        else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
        else {
            filepath = arg;
        }
    }

    if (filepath.empty()) {
        std::cerr << "Error: no input file specified\n";
        print_usage(argv[0]);
        return 1;
    }

    // default: show symbols
    if (!opts.show_symbols && !opts.show_sections &&
        !opts.show_undefined && !opts.show_weak && !opts.show_deps) {
        opts.show_symbols = true;
    }

    ElfParser parser(filepath);
    if (!parser.load()) {
        std::cerr << "Error: failed to load ELF file: " << filepath << "\n";
        return 1;
    }

    Reporter reporter(parser, opts);
    reporter.report();

    return 0;
}