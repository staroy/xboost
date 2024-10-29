#include "timeout.h"
#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "zyre.lua.timeout"

namespace zyre {

  class timeout
  {
    sol::protected_function f_;
    std::mutex& mx_;

    uint64_t last_worked_time_;
    uint64_t interval_;

    uint64_t get_time() const;

  public:
    timeout(uint64_t interval, const sol::protected_function& f, std::mutex& mx);
    ~timeout();
    bool is_call();
    void on();
    void stop();
  };

  std::vector<std::shared_ptr<timeout>> timeouts_;

  void timeout_destroy()
  {
    timeouts_.clear();
  }

  size_t timeout_idle()
  {
    size_t c = 0;
    for(size_t n=0; n<timeouts_.size(); n++)
    {
      auto& t = timeouts_[n];
      if(t->is_call()) { t->on(); c++; }
    }
    return c;
  }

  bool timeout_reg(sol::state_view& lua, std::mutex& mx)
  {
    auto timeout_new = [&](int tm, const sol::protected_function& f) -> std::shared_ptr<timeout> {
      auto p = std::make_shared<timeout>(uint64_t(tm), f, mx);
      timeouts_.push_back(p);
      return p;
    };

    lua.new_usertype<timeout>("timeout",
      sol::call_constructor, timeout_new
    );

    return true;
  }

  timeout::timeout(uint64_t tm, const sol::protected_function& f, std::mutex& mx)
    : interval_(tm * 1000), f_(f), mx_(mx)
  {
    last_worked_time_ = get_time();
  }

  timeout::~timeout()
  {
    stop();
    f_ = sol::lua_nil;
  }

  void timeout::stop()
  {
    for(auto it = timeouts_.begin(); it < timeouts_.end() ; it++)
      if(it->get() == this) {
        auto p = *it; timeouts_.erase(it); return;
      }
  }

  void timeout::on()
  {
    try
    {
      if(f_)
      {
        std::lock_guard<std::mutex> lock(mx_);
        sol::protected_function_result res = f_();
        if (!res.valid())
        {
          sol::error err = res;
          sol::call_status status = res.status();
          MLOG_RED(el::Level::Error, "Lua wrong " << sol::to_string(status) << " error " << err.what());
          stop();
        }
        else if(res.return_count() > 0 && !res.get<bool>(0))
        {
          stop();
        }
        else
        {
          last_worked_time_ = get_time();
        }
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      stop();
    }
  }

  uint64_t timeout::get_time() const
  {
#ifdef _WIN32
    FILETIME fileTime;
    GetSystemTimeAsFileTime(&fileTime);
    unsigned __int64 present = 0;
    present |= fileTime.dwHighDateTime;
    present = present << 32;
    present |= fileTime.dwLowDateTime;
    present /= 10;  // mic-sec
    return present;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
#endif
  }

  bool timeout::is_call()
  {
    uint64_t current_time = get_time();

    if(current_time - last_worked_time_ > interval_)
      return true;

    return false;
  }

}
