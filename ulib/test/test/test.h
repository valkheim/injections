#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ul::test
{
    auto get_lines(std::string&&path) -> std::vector<std::string>;
    extern unsigned char dll_sample_injectee_x64[10752];
    extern unsigned char dll_sample_injectee_x86[8704];
}