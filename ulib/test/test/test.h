#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ul::test
{
    auto get_lines(std::string&&path) -> std::vector<std::string>;
}