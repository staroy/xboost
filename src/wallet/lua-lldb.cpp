#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "lldb.lua"

#include "lldb/lldb.h"
#include "lua.hpp"
#include "lua-lldb.h"
#include "cmsgpack.h"
#include <string>
#include <memory>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

namespace sol
{
    template <>
    struct lua_size<lldb::OutVal> : std::integral_constant<int, 1> {};
    template <>
    struct lua_type_of<lldb::OutVal> : std::integral_constant<sol::type, sol::type::poly> {};

    namespace stack
    {
        // return checker
        template <>
        struct unqualified_checker<lldb::OutVal, type::poly> {
            template <typename Handler>
            static bool check(lua_State* L, int index, Handler&& handler, record& tracking) {
                return true;
            }
        };

        // return getter
        template <>
        struct unqualified_getter<lldb::OutVal> {
            static lldb::OutVal get(lua_State* L, int index, record& tracking) {
                int top = lua_gettop(L);
                lldb::OutVal buf;
                if(top >= index)
                    xpack(L, index, top, buf.data);
                return buf;
            }
        };

        // return pusher
        template <>
        struct unqualified_pusher<lldb::OutVal> {
            static int push(lua_State* L, const lldb::OutVal& buf) {
                if(!buf.data.empty())
                    return xunpack(L, buf.data.data(), buf.data.size());
                lua_pushnil(L);
                return 1;
            }
        };
    }
}

namespace lldb {

  class LBatch;
  
  class LDB : public  std::enable_shared_from_this<LDB>
  {
    friend class LBatch;
  public:
  
  protected:
    DB db_;
  public:
    LDB(const std::string& name) : db_(name) {}
    LDB(const std::string& name, const InVal& pfx) : db_(name, pfx) {};
    
    LDB(const LDB& db) : db_(db.db_) {}
    LDB(const LDB& db, const InVal& pfx) : db_(db.db_, pfx) {}
    
    sol::object getter(sol::stack_object key, sol::this_state L)
    {
      std::string buf;
      xpack(L, key.stack_index(), key.stack_index(), buf);
      InVal pfx{buf.data(), buf.size()};
      return sol::object(L, sol::in_place, std::make_shared<LDB>(*this, pfx));
    }
    void setter(sol::stack_object name, sol::stack_object value, sol::this_state L)
    {
      std::string key;
      xpack(L, name.stack_index(), name.stack_index(), key);
    
      switch(value.get_type())
      {
      case sol::type::lua_nil:
        db_.del({key.data(), key.size()});
        break;
      default:
        {
          std::string val;
          xpack(L, value.stack_index(), value.stack_index(), val);
          db_.put({key.data(), key.size()}, {val.data(), val.size()});
        }
        break;
      }
    }
    
    sol::object at(sol::variadic_args args)
    {
      lua_State *L = args.lua_state();
      std::string key;
      xpack(L, args.stack_index(), args.top(), key);
      InVal pfx{key.data(), key.size()};
      return sol::object(L, sol::in_place, std::make_shared<LDB>(*this, pfx));
    }
    
    sol::variadic_results get(sol::variadic_args args)
    {
      lua_State *L = args.lua_state();
      std::string key;
      xpack(L, args.stack_index(), args.top(), key);
      OutVal val;
      bool s = db_.get({key.data(), key.size()}, val);
      sol::variadic_results rc;
      rc.push_back({ L, sol::in_place, s });
      rc.push_back({ L, sol::in_place, val });
      return rc;
    }
    
    void put(sol::variadic_args args)
    {
      lua_State *L = args.lua_state();
      std::string key, val;
      xpack(L, args.stack_index(), args.top()-1, key);
      xpack(L, args.top(), args.top(), val);
      db_.put({key.data(), key.size()}, {val.data(), val.size()});
    }
    
    void del(sol::variadic_args args)
    {
      lua_State *L = args.lua_state();
      std::string key;
      xpack(L, args.stack_index(), args.top(), key);
      db_.del({key.data(), key.size()});
    }
    
    sol::variadic_results seek(sol::variadic_args args)
    {
      lua_State *L = args.lua_state();
      std::string seek;
      xpack(L, args.stack_index(), args.top(), seek);
      OutVal key, val;
      sol::variadic_results rc;
      if(db_.seek({seek.data(), seek.size()}, key, val)) {
        rc.push_back({ L, sol::in_place, key });
        rc.push_back({ L, sol::in_place, val });
      } else {
        rc.push_back({ L, sol::in_place, sol::lua_nil });
        rc.push_back({ L, sol::in_place, sol::lua_nil });
      }
      return rc;
    }
    
    sol::variadic_results skip(int n, sol::this_state L)
    {
      OutVal key, val;
      sol::variadic_results rc;
      if(db_.skip(key, val, n)) {
        rc.push_back({ L, sol::in_place, key });
        rc.push_back({ L, sol::in_place, val });
      } else {
        rc.push_back({ L, sol::in_place, sol::lua_nil });
        rc.push_back({ L, sol::in_place, sol::lua_nil });
      }
      return rc;
    }
    
    sol::variadic_results first(sol::this_state L)
    {
      OutVal key, val;
      sol::variadic_results rc;
      if(db_.first(key, val)) {
        rc.push_back({ L, sol::in_place, key });
        rc.push_back({ L, sol::in_place, val });
      } else {
        rc.push_back({ L, sol::in_place, sol::lua_nil });
        rc.push_back({ L, sol::in_place, sol::lua_nil });
      }
      return rc;
    }
    
    sol::variadic_results last(sol::this_state L)
    {
      OutVal key, val;
      sol::variadic_results rc;
      if(db_.last(key, val)) {
        rc.push_back({ L, sol::in_place, key });
        rc.push_back({ L, sol::in_place, val });
      } else {
        rc.push_back({ L, sol::in_place, sol::lua_nil });
        rc.push_back({ L, sol::in_place, sol::lua_nil });
      }
      return rc;
    }
    
    sol::variadic_results next(sol::this_state L)
    {
      OutVal key, val;
      sol::variadic_results rc;
      if(db_.next(key, val)) {
        rc.push_back({ L, sol::in_place, key });
        rc.push_back({ L, sol::in_place, val });
      } else {
        rc.push_back({ L, sol::in_place, sol::lua_nil });
        rc.push_back({ L, sol::in_place, sol::lua_nil });
      }
      return rc;
    }
    
    sol::variadic_results prev(sol::this_state L)
    {
      OutVal key, val;
      sol::variadic_results rc;
      if(db_.prev(key, val)) {
        rc.push_back({ L, sol::in_place, key });
        rc.push_back({ L, sol::in_place, val });
      } else {
        rc.push_back({ L, sol::in_place, sol::lua_nil });
        rc.push_back({ L, sol::in_place, sol::lua_nil });
      }
      return rc;
    }
  };


  struct LDB_iterator_state { LDB& db; bool first; };

  sol::variadic_results LDB_pairs_next(sol::user<LDB_iterator_state&> user_it_state, sol::this_state L)
  {
    LDB_iterator_state& it_state = user_it_state;
    if(it_state.first)
    {
      it_state.first = false;
      return it_state.db.first(L);
    }
    return it_state.db.next(L);
  }

  sol::variadic_results LDB_rpairs_prev(sol::user<LDB_iterator_state&> user_it_state, sol::this_state L)
  {
    LDB_iterator_state& it_state = user_it_state;
    if(it_state.first)
    {
      it_state.first = false;
      return it_state.db.last(L);
    }
    return it_state.db.prev(L);
  }

  sol::variadic_results LDB_pairs(LDB& db, sol::this_state L)
  {
    LDB_iterator_state it_state{db, true};
    sol::variadic_results rc;
    rc.push_back({ L, sol::in_place, &LDB_pairs_next });
    rc.push_back({ L, sol::in_place, sol::user<LDB_iterator_state>(std::move(it_state)) });
    rc.push_back({ L, sol::in_place, sol::lua_nil });
    return rc;
  }

  sol::variadic_results LDB_rpairs(LDB& db, sol::this_state L)
  {
    LDB_iterator_state it_state{db, true};
    sol::variadic_results rc;
    rc.push_back({ L, sol::in_place, &LDB_rpairs_prev });
    rc.push_back({ L, sol::in_place, sol::user<LDB_iterator_state>(std::move(it_state)) });
    rc.push_back({ L, sol::in_place, sol::lua_nil });
    return rc;
  }

  class LBatch
  {
    Batch batch_;
  public:
    LBatch(sol::variadic_args args)
    {
      for(size_t n=0; n<args.size(); n++)
        batch_.attach(args.get<LDB&>(n).db_);
    }
    void write() { batch_.write(); }
  };

  bool lua_Reg(sol::state_view& lua, const std::string& root)
  {
    auto ldb_new = [&root](const std::string& path) -> std::shared_ptr<LDB> {
      std::string norm_path(root + "/" + path);
      boost::replace_all(norm_path, "..", "");
      boost::filesystem::create_directory(boost::filesystem::path(norm_path).parent_path());
      return std::make_shared<LDB>(norm_path);
    };
    
    lua.new_usertype<LDB>("LDB",
      sol::call_constructor, ldb_new, "new", ldb_new,
      sol::meta_function::index, &LDB::getter,
      sol::meta_function::new_index, &LDB::setter,
      "at", &LDB::at,
      "get", &LDB::get,
      "put", &LDB::put,
      "del", &LDB::del,
      "seek", &LDB::seek,
      "skip", &LDB::skip,
      "first", &LDB::first,
      "last", &LDB::last,
      "next", &LDB::next,
      "prev", &LDB::prev,
      "pairs", &LDB_pairs,
      "rpairs", &LDB_rpairs
    );
    
    auto batch_new = [](sol::variadic_args args) -> std::shared_ptr<LBatch> {
      return std::make_shared<LBatch>(args);
    };
    
    lua.new_usertype<LBatch>("LBatch",
      sol::call_constructor, batch_new, "new", batch_new,
      "write", &LBatch::write
    );
    return true;
  }
}
