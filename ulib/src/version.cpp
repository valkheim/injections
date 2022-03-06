#include "version.h"

namespace ul
{
  auto getVersion() -> std::string
  {
    static constexpr auto version = "1.0.0";
    return std::string(version);
  }
};  // namespace ul