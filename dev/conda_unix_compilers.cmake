# cxx-compiler >=2 installs unprefixed compilers on PATH (gcc/g++ on Linux, clang/clang++ on macOS)
# and no longer sets CC/CXX.
#
# Do not express this with CMake preset `condition` + `inherits`: the first inherited condition
# wins, so a Unix preset that inherited both Linux and Darwin compiler presets was disabled on macOS
# (`Cannot use disabled configure preset`).
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
    set(
        CMAKE_C_COMPILER
        clang
        CACHE STRING "C compiler"
    )
    set(
        CMAKE_CXX_COMPILER
        clang++
        CACHE STRING "C++ compiler"
    )
elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    set(
        CMAKE_C_COMPILER
        gcc
        CACHE STRING "C compiler"
    )
    set(
        CMAKE_CXX_COMPILER
        g++
        CACHE STRING "C++ compiler"
    )
endif()
