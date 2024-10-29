#pragma once

#include "sol/sol.hpp"

namespace lldb {
  bool lua_Reg(sol::state_view& lua, const std::string& root);
}
