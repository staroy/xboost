#ifndef __zyre_ll_h__
#define __zyre_ll_h__

#include "sol/sol.hpp"

namespace zyre
{
  bool init();
  void destroy();
  bool reg(sol::state_view& lua, std::mutex& mx);
  size_t idle(uint64_t t = 0);
}

#endif
