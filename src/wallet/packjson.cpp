#include "packjson.h"
#include "msgpack.hpp"
#include "easylogging++.h"

#include "rapidjson/reader.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"

#include <stack>

namespace tools
{

  bool pack2json(const std::string& data, std::size_t& off, std::string& out)
  {
    struct visitor
    {
      bool key;
      rapidjson::Writer<rapidjson::StringBuffer>& wr;

      visitor(rapidjson::Writer<rapidjson::StringBuffer>& w) : key(false), wr(w) {}

      bool visit_nil() { return wr.Null(); }
      bool visit_boolean(bool v) { return wr.Bool(v); }
      bool visit_positive_integer(uint64_t v) { return wr.Uint64(v); }
      bool visit_negative_integer(int64_t v) { return wr.Int64(v); }
      bool visit_float32(float v) { return wr.Double(double(v)); }
      bool visit_float64(double v) { return wr.Double(v); }
      bool visit_str(const char* v, uint32_t sz) { if(key) return wr.Key(v, sz); return wr.String(v, sz); }
      bool visit_bin(const char* v, uint32_t sz) {
        wr.StartArray();
        for(uint32_t n=0; n<sz; n++)
            wr.Uint(uint8_t(v[n]));
        wr.EndArray();
        return true;
      }
      bool visit_ext(const char* v, uint32_t sz) {
        wr.StartArray();
        for(uint32_t n=0; n<sz; n++)
            wr.Uint(uint8_t(v[n]));
        wr.EndArray();
        return true;
      }
      bool start_array(uint32_t /*num_elements*/) { return wr.StartArray(); }
      bool start_array_item() { return true; }
      bool end_array_item() { return true; }
      bool end_array() { wr.EndArray(); return true; }
      bool start_map(uint32_t /*num_kv_pairs*/) { return wr.StartObject(); }
      bool start_map_key() { key = true; return true; }
      bool end_map_key() { key = false; return true; }
      bool start_map_value() { return true; }
      bool end_map_value() { return true; }
      bool end_map() { return wr.EndObject(); }
      void parse_error(size_t parsed_offset, size_t error_offset) {
        LOG(ERROR) << "msgpack parse error, parsed offset: " << parsed_offset << ", error offset: " << error_offset;
      }
      void insufficient_bytes(size_t parsed_offset, size_t error_offset) {
        LOG(ERROR) << "msgpack insufficient bytes, parsed offset: " << parsed_offset << ", error offset: " << error_offset;
      }
      bool referenced() const { return false; }
      void set_referenced(bool /*referenced*/) {}
    };

    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> wr(s);
    visitor v(wr);
    if(msgpack::parse(data.data(), data.size(), off, v))
    {
      out = s.GetString();
      return true;
    }
    return false;
  }

  struct msgpack_writer {
    std::stack<std::string>& data;
    msgpack_writer(std::stack<std::string>& stack)
      : data(stack)
    {
    }
    void write(const char* buf, size_t len)
    {
      data.top().insert(data.top().end(), buf, buf+len);
    }
  };

  bool json2pack(const std::string& data, std::string& out)
  {
    struct visitor
    {
      std::stack<std::string> stack;
      msgpack_writer wr;
      msgpack::packer<msgpack_writer> pk;

      visitor() : wr(stack), pk(wr) { stack.push(""); }
      bool Null() { pk.pack_nil(); return true; }
      bool Bool(bool v) { if(v) pk.pack_true(); else pk.pack_false(); return true; }
      bool Int(int v) { pk.pack_int(v); return true; }
      bool Uint(unsigned v) { pk.pack_unsigned_int(v); return true; }
      bool Int64(int64_t v) { pk.pack_int64(v); return true; }
      bool Uint64(uint64_t v) { pk.pack_uint64(v); return true; }
      bool Double(double v) { pk.pack_double(v); return true; }
      bool RawNumber(const char* str, rapidjson::SizeType length, bool /*copy*/)
        { pk.pack_v4raw(length); pk.pack_v4raw_body(str, length); return true; }
      bool String(const char* str, rapidjson::SizeType length, bool /*copy*/)
        { pk.pack_str(length); pk.pack_str_body(str, length); return true; }
      bool StartObject() { stack.push(""); return true; }
      bool Key(const char* str, rapidjson::SizeType length, bool /*copy*/)
        { pk.pack_str(length); pk.pack_str_body(str, length); return true; }
      bool EndObject(rapidjson::SizeType memberCount) {
        std::string arr = stack.top();
        stack.pop();
        pk.pack_map(memberCount);
        std::string& top = stack.top();
        top.insert(top.end(), arr.begin(), arr.end());
        return true;
      }
      bool StartArray() {  stack.push(""); return true; }
      bool EndArray(rapidjson::SizeType elementCount) {
        std::string arr = stack.top();
        stack.pop();
        pk.pack_array(elementCount);
        std::string& top = stack.top();
        top.insert(top.end(), arr.begin(), arr.end());
        return true;
      }
    };

    visitor v;
    rapidjson::Reader reader;
    rapidjson::StringStream ss(data.c_str());
    auto pr = reader.Parse(ss, v);
    if(!pr)
    {
      LOG(ERROR) << "\nError " << static_cast<unsigned>(pr.Offset()) << " : " << GetParseError_En(pr.Code());
      return false;
    }

    out = v.stack.top();
    return true;
}

}
