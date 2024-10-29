#ifndef __zyre_timeout_h__
#define __zyre_timeout_h__

#include "sol/sol.hpp"
#include <mutex>

namespace zyre {

  size_t timeout_idle();
  bool timeout_reg(sol::state_view& lua, std::mutex& mx);
  void timeout_destroy();
}

#endif
