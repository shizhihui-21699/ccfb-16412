# SPDX-License-Identifier: MIT
set(TEST_TARGETS
    test_functional
    test_adversarial
    test_perf
)

foreach(t ${TEST_TARGETS})
    add_executable(${t} ${t}.cpp)
    target_link_libraries(${t} PRIVATE subsafe)
    target_include_directories(${t} PRIVATE
        ${CMAKE_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME ${t} COMMAND ${t})
endforeach()

# Standalone crash reproducer for corpus files (no special engine needed).
add_executable(fuzz_repro fuzz_subtitle.cpp)
target_compile_definitions(fuzz_repro PRIVATE SUBSAFE_STANDALONE_FUZZ=1)
target_link_libraries(fuzz_repro PRIVATE subsafe)

if (SUBSAFE_FUZZ)
    add_executable(fuzz_subtitle fuzz_subtitle.cpp)
    target_compile_options(fuzz_subtitle PRIVATE
        -fsanitize=fuzzer,address,undefined -g)
    target_link_options(fuzz_subtitle PRIVATE
        -fsanitize=fuzzer,address,undefined)
endif()

# Generate a small on-disk corpus for the reproducer / manual fuzzing.
add_custom_target(corpus
    COMMAND ${CMAKE_COMMAND} -E make_directory
            ${CMAKE_BINARY_DIR}/corpus
    COMMAND $<TARGET_FILE:fuzz_repro> --help > /dev/null 2>&1 || true
    COMMENT "corpus directory at ${CMAKE_BINARY_DIR}/corpus"
    VERBATIM)
