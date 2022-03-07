#pragma once

#include <string>

namespace ul
{
  enum class walk_t : bool { WALK_CONTINUE, WALK_STOP };

  auto base_name(std::string const &path) -> std::string;
}  // namespace ul