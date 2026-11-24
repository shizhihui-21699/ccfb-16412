cmake_minimum_required(VERSION 3.16)
project(subsafe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SUBSAFE_ASAN "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(SUBSAFE_TESTS "Build unit and adversarial tests" ON)
option(SUBSAFE_FUZZ "Build fuzz target" OFF)

# Hardening is applied to the library itself, not just tests, so a player
# linking the static build gets the same protections.
add_library(subsafe
    src/internal/common.cpp
    src/style_policy.cpp
    src/internal/parsers.cpp
    src/parsers_text.cpp
    src/parsers_ass.cpp
    src/parsers_more.cpp
    src/parsers_json.cpp
    src/facade.cpp
    src/capi.cpp
)
target_include_directories(subsafe PUBLIC include PRIVATE src)

if (MSVC)
    target_compile_options(subsafe PRIVATE /W4 /permissive- /GS)
else()
    target_compile_options(subsafe PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
        -fstack-protector-strong -D_FORTIFY_SOURCE=2)
endif()

if (SUBSAFE_ASAN AND NOT MSVC)
    target_compile_options(subsafe PUBLIC -fsanitize=address,undefined
        -fno-omit-frame-pointer -g)
    target_link_options(subsafe PUBLIC -fsanitize=address,undefined)
endif()

if (SUBSAFE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Command-line validator / risk inspector.
add_executable(subsafe_check tools/subsafe_check.cpp)
target_link_libraries(subsafe_check PRIVATE subsafe)
if (NOT MSVC)
    target_compile_options(subsafe_check PRIVATE -Wall -Wextra)
endif()
