#include "misc_log_ex.h"

//#undef MONERO_DEFAULT_LOG_CATEGORY
//#define MONERO_DEFAULT_LOG_CATEGORY "zyre::node"

#define VER_MAJOR       0
#define VER_MINOR       1

#define CALL            1
#define CALL_R          2
#define REPLY           3

#define COOKIE_NEXT     uint64_t(-1)

#include "lua.hpp"

#include <string>
#include <iostream>

namespace zyre
{
  struct msgpack_in { const char *p; size_t sz; };
  struct msgpack_out { std::string data; };
}

namespace sol
{
  namespace stack
  {
    // arguments pusher
    int push(lua_State*, zyre::msgpack_in *);
  }
}

#include "sol/sol.hpp"
#include "wallet/cmsgpack.h"

namespace sol
{
  template <>
  struct lua_size<zyre::msgpack_out> : std::integral_constant<int, 1> {};
  template <>
  struct lua_type_of<zyre::msgpack_out> : std::integral_constant<sol::type, sol::type::poly> {};

  namespace stack
  {
    // return checker
    template <>
    struct unqualified_checker<zyre::msgpack_out, type::poly> {
      template <typename Handler>
      static bool check(lua_State* L, int index, Handler&& handler, record& tracking) {
        return true;
      }
    };

    // return getter
    template <>
    struct unqualified_getter<zyre::msgpack_out> {
      static zyre::msgpack_out get(lua_State* L, int index, record& tracking) {
        int top = lua_gettop(L);
        zyre::msgpack_out buf;
        if(top >= index)
          xpack(L, index, top, buf.data);
        return buf;
      }
    };

    // return pusher
    template <>
    struct unqualified_pusher<zyre::msgpack_out> {
      static int push(lua_State* L, const zyre::msgpack_out& buf) {
        if(!buf.data.empty())
          return xunpack(L, buf.data.data(), buf.data.size());
        lua_pushnil(L);
        return 1;
      }
    };

    // arguments pusher
    int push(lua_State *L, zyre::msgpack_in *p)
    {
      if(p->p && p->sz>0)
        return xunpack(L, p->p, p->sz);
      lua_pushnil(L);
      return 1;
    }
  }
}

#include <string>
#include <iostream>

#include "zyre.h"
#include "sodium.h"

#include "certs.h"
#include "auth.h"
#include "timeout.h"
#include "wallet/pack.hpp"

namespace zyre {

  void *ctx = nullptr;
  certs_t *certs = nullptr;
  zactor_t *auth = nullptr;

  zcert_t *new_cert(const std::string& pin)
  {
    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES] = {
      128,165, 28,003,132,201,031,250,142,184,186,024, 8,167,68,075,
      053,231,105,160,230,167,144,201,176,158, 68,162,78,128,68,109
    };

    uint8_t seed[crypto_box_SEEDBYTES];
    
    if(0 != ::crypto_pwhash_scryptsalsa208sha256(
      seed, crypto_box_SEEDBYTES, pin.c_str(), pin.length(), salt,
      crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
      crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE))
    {
      MLOG_RED(el::Level::Error, "Could not create seed");
      return nullptr;
    }
    
    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    if(0 != ::crypto_box_seed_keypair(pk, sk, seed))
    {
      MLOG_RED(el::Level::Error, "Could not create certificate");
      return nullptr;
    }
    
    return zcert_new_from(pk, sk);
  }

  class caller;

  class node
  {
  friend class caller;

    zyre_t *node_;
    zpoller_t *poller_;
    std::map<std::string, tools::func_r_t> meth_r_;
    typedef struct { time_t t; tools::func_t f; } r_info_t;
    std::map<uint64_t, r_info_t> reply_;
    size_t reply_timeout_;
    std::vector<std::string> groups_;
    static uint64_t cookie_n_;

  protected:
    std::mutex& lua_mx_;

  public:
    static std::vector<node*> nodes_;

    node(const std::string& name, const std::string& pin, std::mutex& mx)
      : reply_timeout_(60*10), lua_mx_(mx)
    {
      if(!ctx)
        return;

      if(!certs)
        certs = certs_new();

      if(!auth)
        auth = zactor_new(domain_auth, certs);

      node_ = zyre_new( name.c_str() );
      if (!node_)
      {
        MLOG_RED(el::Level::Warning, "Could not create new zyre node");
        return;
      }
      
      if(!pin.empty())
      {
        std::string domain = ("zap-" + name).c_str();
        zyre_set_zap_domain(node_, domain.c_str());
      
        zcert_t *cert = new_cert(pin);
      
        zyre_set_zcert(node_, zcert_new_from(zcert_public_key(cert), zcert_secret_key(cert)));
        zyre_set_header(node_, "X-PUBLICKEY", "%s", zcert_public_txt(cert));

        //zyre_set_verbose(node_);

        if(!certs_lookup(certs, domain.c_str(), zcert_public_txt(cert)))
        {
           certs_insert(certs, domain.c_str(), &cert);
        }
      }
      
      zyre_start(node_);

      poller_ = zpoller_new(zyre_socket(node_), NULL);

      nodes_.push_back(this);
    }

    ~node()
    {
      for(auto it=nodes_.begin(); it<nodes_.end(); it++)
        if(*it == this) { nodes_.erase(it); break; }

      clear();
    }

    void clear()
    {
      zpoller_destroy(&poller_);
      if(node_) zyre_stop (node_);
      zclock_sleep (100);
      zyre_destroy (&node_);

      if(nodes_.size() == 0)
      {
        if(auth)
          zactor_destroy(&auth);

        if(certs)
          certs_destroy(&certs);
      }
    }

    void join(sol::variadic_args args)
    {
      if(!node_)
        return;
      lua_State *L = args.lua_state();
      int limit = args.top();
      for(int n=args.stack_index(); n<=limit; n++)
      {
        std::string name = sol::stack_object(L, n).as<std::string>();
        zyre_join(node_, name.c_str());
        groups_.push_back(name);
      }
    }

    void leave(sol::variadic_args args)
    {
      if(!node_)
        return;
      lua_State *L = args.lua_state();
      int limit = args.top();
      for(int n=args.stack_index(); n<=limit; n++)
      {
        std::string name = sol::stack_object(L, n).as<std::string>();
        zyre_leave(node_, name.c_str());
        for(auto it=groups_.begin(); it<groups_.end(); it++)
          if(*it == name) { groups_.erase(it); break; }
      }
    }

    void setter(sol::stack_object k, sol::stack_object v, sol::this_state L)
    {
      if(v.get_type() == sol::type::function) {
        sol::protected_function f = v.as<sol::protected_function>();
        on_func_r(k.as<std::string>(), [this,f](const std::string& pars, tools::func_t r){
          msgpack_in s{pars.data(), pars.size()};
          try {
            std::lock_guard<std::mutex> lock(lua_mx_);
            sol::protected_function_result res = f(this, s);
            if (res.valid()) {
              if(res.return_count()>0) {
                std::string buf;
                xpack(res.lua_state(),
                  res.stack_index(),
                  res.stack_index()+res.return_count()-1, buf);
                r(buf);
              }
            } else {
              sol::error err = res;
              MLOG_RED(el::Level::Error, err.what());
            }
          }
          catch(const std::exception& e)
          {
            MLOG_RED(el::Level::Error, e.what());
          }
        });
      }
      else if(v.get_type() == sol::type::boolean)
      {
        if(!v.as<bool>())
          remove_func_r(k.as<std::string>());
      }
      else if(v.is<sol::lua_nil_t>())
      {
        remove_func_r(k.as<std::string>());
      }
    }

    sol::object getter(sol::stack_object k, sol::this_state L);

    void remove_func_r(const std::string& cmd)
    {
      auto it = meth_r_.find(cmd);
      if(it != meth_r_.end())
        meth_r_.erase(it);
    }

    void on_func_r(const std::string& cmd, const tools::func_r_t& f)
    {
      meth_r_[cmd] = f;
    }

    inline uint64_t do_send(const std::string& group, const std::string& fname, const std::string& pars, uint64_t cookie = COOKIE_NEXT)
    {
       std::vector<std::string> groups{group};
       return do_send(groups, fname, pars, cookie);
    }

    uint64_t do_send(const std::vector<std::string>& groups, const std::string& fname, const std::string& pars, uint64_t cookie = COOKIE_NEXT)
    {
      if(!node_)
        return 0;

      if(cookie == COOKIE_NEXT) {
        cookie_n_++;
        cookie = cookie_n_;
      }

      std::stringstream ss;
      msgpack::pack(ss, uint8_t(VER_MAJOR));
      msgpack::pack(ss, uint8_t(VER_MINOR));
      msgpack::pack(ss, uint8_t(cookie ? CALL_R : CALL));
      msgpack::pack(ss, fname);
      if(cookie) msgpack::pack(ss, cookie);
      msgpack::pack(ss, pars);
      std::string data = ss.str();

      for(auto& group : groups)
      {    
        zmsg_t *msg = zmsg_new();
        zframe_t *frame = zframe_new(data.data(), data.size());
        zmsg_add(msg, frame);
        zyre_shout(node_, group.c_str(), &msg);
      }

      return cookie;
    }

    uint64_t do_reply(std::string& peer, uint64_t cookie, const std::string& res)
    {
      if(!node_)
        return cookie;

      std::stringstream ss;
      msgpack::pack(ss, uint8_t(VER_MAJOR));
      msgpack::pack(ss, uint8_t(VER_MINOR));
      msgpack::pack(ss, uint8_t(REPLY));
      msgpack::pack(ss, cookie);
      msgpack::pack(ss, res);
      std::string data = ss.str();

      zmsg_t *msg = zmsg_new();
      zframe_t *frame = zframe_new(data.data(), data.size());
      zmsg_add(msg, frame);
      zyre_whisper(node_, peer.c_str(), &msg);

      return cookie;
    }

    void do_send_r(const std::string& fname, const std::string& pars, const tools::func_t& r)
    {
      uint64_t cookie = do_send(groups_, fname, pars);
      reply_[cookie] = { time_t(time(nullptr) + reply_timeout_), r };
    }

    void do_send(const std::string& fname, const std::string& pars)
    {
      do_send(groups_, fname, pars, 0);
    }

    size_t idle(uint64_t t)
    {
      if(!node_)
        return 0;

      void *which = zpoller_wait(poller_, t);
      try
      {
        if(which == zyre_socket(node_))
        {
          zmsg_t *msg = zmsg_recv(which);
          if (!msg) {
            MLOG_RED(el::Level::Error, "Interrupted zyre node");
            return 0;
          }

          bool is_shout = false; bool is_whisper = false;
    
          char *event = zmsg_popstr(msg);

          is_whisper = (0 == strcmp("WHISPER", event));
          if(!is_whisper) {
            is_shout = (0 == strcmp("SHOUT", event));
            if(!is_shout) {
              free(event); return 1;
            }
          }

          char *peer  = zmsg_popstr(msg);
          char *name  = zmsg_popstr(msg);
          char *group = 0;

          std::string reply_peer = peer;

          if(!is_whisper)
            group = zmsg_popstr(msg);

          free(event);
          free(peer);
          free(name);
          if(group)
            free(group);

          zframe_t *frame = zmsg_pop(msg);
          if(!frame)
            throw std::runtime_error("frame of data is null");

          size_t off = 0;
          void * data = zframe_data(frame);
          size_t size = zframe_size(frame);

          uint8_t  ver_major = 0;
          uint8_t  ver_minor = 0;
          uint8_t  op_type   = 0;
          uint64_t cookie    = 0;
          std::string fname, pars;

          msgpack::unpack(static_cast<const char *>(data), size, off).get().convert(ver_major);
          msgpack::unpack(static_cast<const char *>(data), size, off).get().convert(ver_minor);
          msgpack::unpack(static_cast<const char *>(data), size, off).get().convert(op_type);

          if(op_type == REPLY)
          {
            if(!is_whisper)
              throw std::runtime_error("reply must be whisper");
          }
          else
            msgpack::unpack(static_cast<const char *>(data), size, off).get().convert(fname);

          if(op_type == CALL)
          {
            if(!is_shout)
              throw std::runtime_error("call must be shout");
          }
          else
            msgpack::unpack(static_cast<const char *>(data), size, off).get().convert(cookie);

          if(op_type == CALL_R)
          {
            if(!is_shout)
              throw std::runtime_error("call with reply must be shout");
          }

          msgpack::unpack(static_cast<const char *>(data), size, off).get().convert(pars);
    
          zframe_destroy(&frame);
          zmsg_destroy(&msg);

          if(ver_minor >= VER_MINOR && ver_major >= VER_MAJOR)
          {
            if(op_type == REPLY)
            {
              const auto& f = reply_.find(cookie);
              if(f != reply_.end())
                f->second.f(pars);
            }
            else if(op_type == CALL_R)
            {
              const auto& f = meth_r_.find(fname);
              if(f != meth_r_.end())
              {
                f->second(pars, [&](const std::string& res){
                  do_reply(reply_peer, cookie, res);
                });
              }
            }
            else if(op_type == CALL)
            {
              const auto& f = meth_r_.find(fname);
              if(f != meth_r_.end())
              {
                f->second(pars, [&](const std::string& res){});
              }
            }
          }
        }

        // remove timeout replyes
        std::vector<std::map<uint64_t, r_info_t>::iterator> r_timeout;
        for(auto it=reply_.begin(); it!=reply_.end(); it++)
          if(it->second.t < time(nullptr))
            r_timeout.push_back(it);
        for(auto it : r_timeout)
          reply_.erase(it);
      }
      catch(const std::exception& e)
      {
        MLOG_RED(el::Level::Error, e.what());
      }
      catch(...)
      {
        MLOG_RED(el::Level::Error, "unqnow");
      }
      return 1;
    }
  };

  uint64_t node::cookie_n_ = 1;
  std::vector<node*> node::nodes_;

  class caller
  {
    zyre::node& zyre_;
    std::string name_;

  public:
    caller(node& node, const std::string& name)
      : zyre_(node)
      , name_(name)
    {}

    void on(sol::variadic_args args)
    {
      lua_State *L = args.lua_state();
      int limit = args.top();

      class callback_t
      {
        bool m_;
        sol::table t_;
        sol::protected_function f_;
        std::mutex& lua_mx_;
      public:
        callback_t(const sol::protected_function& f, std::mutex& mx)
            : m_(false), f_(f), lua_mx_(mx)
        {}
        callback_t(const sol::protected_function& f, const sol::stack_object& t, std::mutex& mx)
            : m_(true), f_(f), t_(t.as<sol::table>()), lua_mx_(mx)
        {}
        void on(const std::string& pars)
        {
          msgpack_in s{pars.data(), pars.size()};
          try
          {
            if(m_)
            {
              std::lock_guard<std::mutex> lock(lua_mx_);
              sol::protected_function_result res = f_(t_, s);
              if (!res.valid())
              {
                sol::error err = res;
                MLOG_RED(el::Level::Error, err.what());
              }
            }
            else
            {
              std::lock_guard<std::mutex> lock(lua_mx_);
              sol::protected_function_result res = f_(s);
              if (!res.valid())
              {
                sol::error err = res;
                MLOG_RED(el::Level::Error, err.what());
              }
            }
          }
          catch(const std::exception& e)
          {
            MLOG_RED(el::Level::Error, e.what());
          }
        }
      };

      tools::func_t r;
      if(lua_type(L, limit) == LUA_TFUNCTION)
      {
        std::shared_ptr<callback_t> callback(
          new callback_t(sol::stack_object(L, limit).as<sol::protected_function>(), zyre_.lua_mx_)
        );
        r = std::bind(&callback_t::on, callback, std::placeholders::_1);
        limit--;
      }
      else if(lua_type(L, limit) == LUA_TTABLE && lua_type(L, limit-1) == LUA_TFUNCTION)
      {
        std::shared_ptr<callback_t> callback(
          new callback_t(
            sol::stack_object(L, limit-1).as<sol::protected_function>(),
            sol::stack_object(L, limit),
            zyre_.lua_mx_
          )
        );
        r = std::bind(&callback_t::on, callback, std::placeholders::_1);
        limit-=2;
      }

      std::string pars;
      xpack(L, args.stack_index() + 1, limit, pars);
      if(r)
        zyre_.do_send_r(name_, pars, r);
      else
        zyre_.do_send(name_, pars);
    }
  };

  sol::object node::getter(sol::stack_object k, sol::this_state L)
  {
    return sol::object(L, sol::in_place, std::make_shared<caller>(*this, k.as<std::string>()));
  }

  bool reg(sol::state_view& lua, std::mutex& mx)
  {
    timeout_reg(lua, mx);

    lua.new_usertype<caller>(
      "call_type", sol::no_constructor,
      sol::meta_function::call, &caller::on);

    lua.new_usertype<node>("zyre",
      sol::meta_function::construct,
      sol::factories(
        [&mx](const std::string& name, const std::string& pin) { return std::make_shared<node>(name, pin, mx); },
        [&mx](sol::object, const std::string& name, const std::string& pin) { return std::make_shared<node>(name, pin, mx); }),
      sol::call_constructor,
        [&mx](const std::string& name, const std::string& pin) { return std::make_shared<node>(name, pin, mx); },
      sol::meta_function::new_index, &node::setter,
      sol::meta_function::index, &node::getter,
      "join", &node::join,
      "leave", &node::leave);
    return true;
  }

  bool init()
  {
    if(!ctx)
      ctx = zsys_init();

    return true;
  }

  void destroy()
  {
    std::vector<node*> nodes = node::nodes_;
    node::nodes_.clear();

    timeout_destroy();

    for(auto it=nodes.begin(); it<nodes.end(); it++)
      (*it)->clear();
  }

  size_t idle(uint64_t t)
  {
    for(auto it=node::nodes_.begin(); it<node::nodes_.end(); it++)
      (*it)->idle(t);

    timeout_idle();
    return 1;
  }
}
