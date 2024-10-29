#ifndef __tools_pack_h__
#define __tools_pack_h__

#include <vector>
#include <string>
#include <sstream>
#include <functional>

#include "msgpack.hpp"

namespace tools {

  typedef std::function<void(const std::string& /*params*/)> func_t;
  typedef std::function<void(const std::string& /*params*/, func_t /*reply*/)> func_r_t;

  template<typename A1>
  void to_buf(std::string& buf, A1 a1)
  {
    std::stringstream ss;
    msgpack::pack(ss, a1);
    buf = ss.str();
  }

  template<typename A1, typename A2>
  void to_buf(std::string& buf, A1 a1, A2 a2)
  {
    std::stringstream ss;
    msgpack::pack(ss, a1);
    msgpack::pack(ss, a2);
    buf = ss.str();
  }

  template<typename A1, typename A2, typename A3>
  void to_buf(std::string& buf, A1 a1, A2 a2, A3 a3)
  {
    std::stringstream ss;
    msgpack::pack(ss, a1);
    msgpack::pack(ss, a2);
    msgpack::pack(ss, a3);
    buf = ss.str();
  }

  template<typename A1, typename A2, typename A3, typename A4>
  void to_buf(std::string& buf, A1 a1, A2 a2, A3 a3, A4 a4)
  {
    std::stringstream ss;
    msgpack::pack(ss, a1);
    msgpack::pack(ss, a2);
    msgpack::pack(ss, a3);
    msgpack::pack(ss, a4);
    buf = ss.str();
  }

  template<typename A1, typename A2, typename A3, typename A4, typename A5>
  void to_buf(std::string& buf, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5)
  {
    std::stringstream ss;
    msgpack::pack(ss, a1);
    msgpack::pack(ss, a2);
    msgpack::pack(ss, a3);
    msgpack::pack(ss, a4);
    msgpack::pack(ss, a5);
    buf = ss.str();
  }

  template<typename A1, typename A2, typename A3, typename A4, typename A5, typename A6>
  void to_buf(std::string& buf, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6)
  {
    std::stringstream ss;
    msgpack::pack(ss, a1);
    msgpack::pack(ss, a2);
    msgpack::pack(ss, a3);
    msgpack::pack(ss, a4);
    msgpack::pack(ss, a5);
    msgpack::pack(ss, a6);
    buf = ss.str();
  }

  template<typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7>
  void to_buf(std::string& buf, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7)
  {
    std::stringstream ss;
    msgpack::pack(ss, a1);
    msgpack::pack(ss, a2);
    msgpack::pack(ss, a3);
    msgpack::pack(ss, a4);
    msgpack::pack(ss, a5);
    msgpack::pack(ss, a6);
    msgpack::pack(ss, a7);
    buf = ss.str();
  }

  template<typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8>
  void to_buf(std::string& buf, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8)
  {
    std::stringstream ss;
    msgpack::pack(ss, a1);
    msgpack::pack(ss, a2);
    msgpack::pack(ss, a3);
    msgpack::pack(ss, a4);
    msgpack::pack(ss, a5);
    msgpack::pack(ss, a6);
    msgpack::pack(ss, a7);
    msgpack::pack(ss, a8);
    buf = ss.str();
  }

  template<typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9>
  void to_buf(std::string& buf, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9)
  {
    std::stringstream ss;
    msgpack::pack(ss, a1);
    msgpack::pack(ss, a2);
    msgpack::pack(ss, a3);
    msgpack::pack(ss, a4);
    msgpack::pack(ss, a5);
    msgpack::pack(ss, a6);
    msgpack::pack(ss, a7);
    msgpack::pack(ss, a8);
    msgpack::pack(ss, a9);
    buf = ss.str();
  }

  template<typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10>
  void to_buf(std::string& buf, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10)
  {
    std::stringstream ss;
    msgpack::pack(ss, a1);
    msgpack::pack(ss, a2);
    msgpack::pack(ss, a3);
    msgpack::pack(ss, a4);
    msgpack::pack(ss, a5);
    msgpack::pack(ss, a6);
    msgpack::pack(ss, a7);
    msgpack::pack(ss, a8);
    msgpack::pack(ss, a9);
    msgpack::pack(ss, a10);
    buf = ss.str();
  }

  struct resp_t
  {
    func_t f_;

    resp_t(func_t f) : f_(f) {}

    template<typename... A>
    void operator ()(const A&... args)
    {
        std::string buf;
        to_buf(buf, args...);
        f_(buf);
    }
  };

  #define UNPACK(n) A##n a##n; { msgpack::object_handle o = msgpack::unpack(pars.data(), pars.size(), off); o.get().convert(a##n); }

  template<typename T>
  func_t fwrap(void(T::*f)(), T *p)
  {
    auto F = std::bind(f, p);
    return [F](const std::string& pars) -> bool {
        F();
        return true;
    };
  }

  template<typename T>
  func_r_t fwrap_r(void(T::*f)(resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1);
    return [F](const std::string& pars, func_t r) -> bool {
        F(resp_t(r));
        return true;
    };
  }

  template<typename T, typename A1>
  func_t fwrap(void(T::*f)(const A1&), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1);
    return [F](const std::string& pars) -> bool {
        size_t off = 0; UNPACK(1);
        F(a1);
        return true;
    };
  }

  template<typename T, typename A1>
  func_r_t fwrap_r(void(T::*f)(const A1&, resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2);
    return [F](const std::string& pars, func_t r) -> bool {
        size_t off = 0; UNPACK(1);
        F(a1, resp_t(r));
        return true;
    };
  }

  template<typename T, typename A1, typename A2>
  func_t fwrap(void(T::*f)(const A1&, const A2&), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2);
    return [F](const std::string& pars) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2);
        F(a1, a2);
        return true;
    };
  }

  template<typename T, typename A1, typename A2>
  func_r_t fwrap_r(void(T::*f)(const A1&, const A2&, resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    return [F](const std::string& pars, func_t r) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2);
        F(a1, a2, resp_t(r));
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3>
  func_t fwrap(void(T::*f)(const A1&, const A2&, const A3&), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    return [F](const std::string& pars) {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3);
        F(a1, a2, a3);
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3>
  func_r_t fwrap_r(void(T::*f)(const A1&, const A2&, const A3&, resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
    return [F](const std::string& pars, func_t r) {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3);
        F(a1, a2, a3, resp_t(r));
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4>
  func_t fwrap(void(T::*f)(const A1&, const A2&, const A3&, const A4&), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
    return [F](const std::string& pars) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4);
        F(a1, a2, a3, a4);
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4>
  func_r_t fwrap_r(void(T::*f)(const A1&, const A2&, const A3&, const A4&, resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);
    return [F](const std::string& pars, func_t r) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4);
        F(a1, a2, a3, a4, resp_t(r));
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5>
  func_t fwrap(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);
    return [F](const std::string& pars) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5);
        F(a1, a2, a3, a4, a5);
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5>
  func_r_t fwrap_r(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6);
    return [F](const std::string& pars, func_t r) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5);
        F(a1, a2, a3, a4, a5, resp_t(r));
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6>
  func_t fwrap(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, const A6&), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6);
    return [F](const std::string& pars) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5); UNPACK(6);
        F(a1, a2, a3, a4, a5, a6);
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6>
  func_r_t fwrap_r(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, const A6&, resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7);
    return [F](const std::string& pars, func_t r) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5); UNPACK(6);
        F(a1, a2, a3, a4, a5, a6, resp_t(r));
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7>
  func_t fwrap(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, const A6&, const A7&), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7);
    return [F](const std::string& pars) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5); UNPACK(6); UNPACK(7);
        F(a1, a2, a3, a4, a5, a6, a7);
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7>
  func_r_t fwrap_r(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, const A6&, const A7&, resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8);
    return [F](const std::string& pars, func_t r) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5); UNPACK(6); UNPACK(7);
        F(a1, a2, a3, a4, a5, a6, a7, resp_t(r));
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8>
  func_t fwrap(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, const A6&, const A7&, const A8&), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8);
    return [F](const std::string& pars) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5); UNPACK(6); UNPACK(7); UNPACK(8);
        F(a1, a2, a3, a4, a5, a6, a7, a8);
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8>
  func_r_t fwrap_r(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, const A6&, const A7&, const A8&, resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9);
    return [F](const std::string& pars, func_t r) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5); UNPACK(6); UNPACK(7); UNPACK(8);
        F(a1, a2, a3, a4, a5, a6, a7, a8, resp_t(r));
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9>
  func_t fwrap(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, const A6&, const A7&, const A8&, const A9&), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9);
    return [F](const std::string& pars) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5); UNPACK(6); UNPACK(7); UNPACK(8); UNPACK(9);
        F(a1, a2, a3, a4, a5, a6, a7, a8, a9);
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9>
  func_r_t fwrap_r(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, const A6&, const A7&, const A8&, const A9&, resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9, std::placeholders::_10);
    return [F](const std::string& pars, func_t r) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5); UNPACK(6); UNPACK(7); UNPACK(8); UNPACK(9);
        F(a1, a2, a3, a4, a5, a6, a7, a8, a9, resp_t(r));
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10>
  func_t fwrap(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, const A6&, const A7&, const A8&, const A9&, const A10&), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9, std::placeholders::_10);
    return [F](const std::string& pars) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5); UNPACK(6); UNPACK(7); UNPACK(8); UNPACK(9); UNPACK(10);
        F(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
        return true;
    };
  }

  template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10>
  func_r_t fwrap_r(void(T::*f)(const A1&, const A2&, const A3&, const A4&, const A5&, const A6&, const A7&, const A8&, const A9&, const A10&, resp_t), T *p)
  {
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9, std::placeholders::_10, std::placeholders::_11);
    return [F](const std::string& pars, func_t r) -> bool {
        size_t off = 0; UNPACK(1); UNPACK(2); UNPACK(3); UNPACK(4); UNPACK(5); UNPACK(6); UNPACK(7); UNPACK(8); UNPACK(9); UNPACK(10);
        F(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, resp_t(r));
        return true;
    };
  }

}

#endif
