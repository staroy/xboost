#ifndef __wallet_lua_json_h__
#define __wallet_lua_json_h__

#include "sol/sol.hpp"

namespace tools { namespace lua {

  void lua_json_reg(sol::table& lua, sol::state_view& L);

}}

#endif