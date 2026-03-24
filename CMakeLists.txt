cmake_minimum_required(VERSION 3.14)
project(elf-analyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -O2)

add_executable(elf-analyzer
    src/main.cpp
    src/elf_parser.cpp
    src/reporter.cpp
)

target_include_directories(elf-analyzer PRIVATE src)

install(TARGETS elf-analyzer DESTINATION bin)