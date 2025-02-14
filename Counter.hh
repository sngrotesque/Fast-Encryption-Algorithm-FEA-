#pragma once
#include "Common.hh"
#include <string>

constexpr wU32 COUNTER_BLOCK_SIZE = 16;

class Counter {
private:
    wByte counter[COUNTER_BLOCK_SIZE]{};

public:
    Counter() = default;

    Counter(const wByte *nonce, wU32 size, wSize begin);
    Counter(const char *nonce, wU32 size, wSize begin);
    Counter(std::string nonce, wSize begin);

public:
    wByte *get() noexcept;
    void clean() noexcept;
    void step_up() noexcept;
};