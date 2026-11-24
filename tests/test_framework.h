// SPDX-License-Identifier: MIT
// Tiny dependency-free test framework: a failure records the location and the
// test continues, with a process exit code aggregated at the end.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace test {

struct Case {
    const char* name;
    void (*fn)();
};

inline std::vector<Case>& registry() {
    static std::vector<Case> r;
    return r;
}

inline int& failures() { static int f = 0; return f; }
inline int& checks() { static int c = 0; return c; }

struct Registrar {
    Registrar(const char* name, void (*fn)()) {
        registry().push_back({name, fn});
    }
};

inline void check(bool cond, const char* expr, const char* file, int line) {
    ++checks();
    if (!cond) {
        ++failures();
        std::fprintf(stderr, "  FAIL %s:%d  %s\n", file, line, expr);
    }
}

template <typename A, typename B>
void checkEq(const A& a, const B& b, const char* sa, const char* sb,
             const char* file, int line) {
    ++checks();
    if (!(a == b)) {
        ++failures();
        std::fprintf(stderr, "  FAIL %s:%d  %s == %s\n", file, line, sa, sb);
    }
}

} // namespace test

#define TEST(name)                                                          \
    static void name();                                                     \
    static test::Registrar reg_##name(#name, name);                        \
    static void name()

#define CHECK(cond) test::check(static_cast<bool>(cond), #cond, __FILE__, __LINE__)
#define CHECK_EQ(a, b) test::checkEq((a), (b), #a, #b, __FILE__, __LINE__)

#define RUN_ALL_TESTS()                                                     \
    int main() {                                                            \
        for (const auto& c : test::registry()) {                            \
            int before = test::failures();                                 \
            std::printf("[ RUN  ] %s\n", c.name);                          \
            c.fn();                                                         \
            if (test::failures() == before) std::printf("[ PASS ] %s\n",   \
                                                        c.name);            \
            else std::printf("[ FAIL ] %s\n", c.name);                     \
        }                                                                   \
        std::printf("\n%d checks, %d failures\n", test::checks(),         \
                    test::failures());                                      \
        return test::failures() ? 1 : 0;                                   \
    }
