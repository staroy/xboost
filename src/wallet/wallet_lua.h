#pragma once

#include "lua.hpp"

namespace tools { namespace lua {
  struct msgpack_in { const char *p; size_t sz; };
  struct msgpack_out { std::string data; };
}}

namespace sol
{
  namespace stack
  {
    // arguments pusher
    int push(lua_State*, tools::lua::msgpack_in *);
  }
}

#include "sol/sol.hpp"

#include "pack.hpp"

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"

#include <mutex>
#include <thread>

namespace tools {

  class wallet2;

  namespace lua {

    class wallet2_interface;
   
    class simple
    {
      friend class wallet2_interface;

      wallet2                             *wallet_;
      std::shared_ptr<wallet2_interface>  interface_;
      std::string                         root_path_;

      sol::state                          L_;
      std::mutex                          lua_mx_;

    
    protected:
      std::map<std::string, sol::protected_function> meth_;
    
    public:
      simple(wallet2 *wallet);
      ~simple();
    
      void clear();

      void on_message_chat_received(uint64_t height, const crypto::hash& txid, uint64_t type, uint64_t freq, const cryptonote::account_public_address& chat, uint64_t n, const cryptonote::account_public_address& sender, const std::string& text, const std::string& description, const std::string& short_name, bool enable_comments, uint64_t timestamp, const crypto::hash& parent);
      void on_message_chat_removed(const crypto::hash& txid);
      void on_atomic_swap_x_received(const crypto::hash& txid, const std::string& x);
    
      bool call(const std::string& name, const std::string& pars, func_t reply);
      bool call(const std::string& name, const std::string& pars);
    
      static bool reg(sol::state_view& lua, simple *s = nullptr);
    
      bool init();

      size_t idle(uint64_t t = 0);
    };
  }
}
