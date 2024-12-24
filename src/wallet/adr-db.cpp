#include <boost/algorithm/string.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/filesystem.hpp>
#include "common/util.h"
#include "misc_log_ex.h"
#include "misc_language.h"
#include "wallet_errors.h"
#include "adr-db.h"
#include "cryptonote_config.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.adr_db"

namespace tools
{

  crypto::hash adr_db::to_salt_hash(const crypto::hash &chat)
  {
    crypto::hash hash[] = {chat, m_salt}, res;
    crypto::tree_hash(hash, 2, res);
    return res;
  }

  crypto::hash adr_db::address_to_hash(const cryptonote::account_public_address &chat)
  {
    crypto::hash res;
    crypto::cn_fast_hash(&chat, sizeof(chat), res);
    return res;
  }

  crypto::hash str_to_hash(const std::string &str)
  {
    crypto::hash res;
    crypto::cn_fast_hash(str.data(), str.size(), res);
    return res;
  }

  struct addr_row_cipher
  {
    std::string data;
    crypto::public_key key;
    crypto::chacha_iv iv;
  
    BEGIN_SERIALIZE_OBJECT()
      FIELD(data)
      FIELD(key)
      FIELD(iv)
    END_SERIALIZE()
  };

  adr_db::adr_db(const std::string& filename, wallet2 *wallet, uint64_t cache_limit)
    : m_db(filename)
    , m_block(m_db, "B")
    , m_data(m_db, "D")
    , m_chat(m_db, "C")
    , m_idx(m_db, "I")
    , m_tag(m_db, "T")
    , m_attr(m_db, "A")
    , m_cache_limit(cache_limit)
    , m_wallet(wallet)
  {
    crypto::cn_fast_hash(m_wallet->get_account().get_keys().m_view_secret_key.data, sizeof(crypto::secret_key), m_salt);
  }

  bool adr_db::add(const wallet2::address_book_row& in_data, uint64_t& row_id)
  {
    try
    {
      {
        lldb::OutVal key, val;
        if(m_data.last(key, val))
          row_id = key.get<uint64_t>() + 1;
        else
          row_id = 0;
      }

      bool is_anon = in_data.m_address.m_spend_public_key == crypto::null_pkey || in_data.m_address.m_view_public_key == crypto::null_pkey;
      crypto::hash addr = is_anon ? in_data.m_address_hash : address_to_hash(in_data.m_address);

      wallet2::address_book_row data(in_data);
      data.m_address_hash = addr;

      std::stringstream oss1;
      binary_archive<true> ar1(oss1);
      THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar1, data),
        tools::error::wallet_internal_error, "Failed serialize message");

      addr_row_cipher cipher;
      THROW_WALLET_EXCEPTION_IF(
        !wallet2::encrypt(m_wallet->get_address().m_view_public_key, oss1.str(), cipher.data, cipher.key, cipher.iv),
          tools::error::wallet_internal_error, "Failed encrypt message cipher");

      std::stringstream oss2;
      binary_archive<true> ar2(oss2);
      THROW_WALLET_EXCEPTION_IF(
        !::serialization::serialize(ar2, cipher),
          tools::error::wallet_internal_error, "Failed serialize message");

      lldb::Batch B(m_data, m_idx);

      m_data.put(row_id, {oss2.str().data(), oss2.str().size()});
      m_idx.put(to_salt_hash(addr), row_id);

      B.write();

      std::lock_guard<std::mutex> lock(m_mutex_data);

      m_cache_data[row_id] = data;
      m_cache_idx[addr] = row_id;
      m_cache_order.insert(m_cache_order.begin(), row_id);

      if(m_cache_order.size() > m_cache_limit)
      {
        uint64_t id = m_cache_order.back();
        const auto& it = m_cache_idx.find(address_to_hash(m_cache_data[id].m_address));
        if(it != m_cache_idx.end())
           m_cache_idx.erase(it);
        m_cache_data.erase(m_cache_order.back());
        m_cache_order.pop_back();
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return true;
  }

  bool adr_db::set(uint64_t row_id, const wallet2::address_book_row& in_data)
  {
    try
    {
      uint64_t sz = 0;

      {
        lldb::OutVal key, val;
        if(m_data.last(key, val))
          sz = key.get<uint64_t>() + 1;
      }

      crypto::hash addr = address_to_hash(in_data.m_address);

      THROW_WALLET_EXCEPTION_IF(row_id >= sz,
        tools::error::wallet_internal_error, "Failed row id >= size");

      uint64_t id;
      THROW_WALLET_EXCEPTION_IF(!get_id(addr, id) || id != row_id,
        tools::error::wallet_internal_error, "Failed address of row id");

      wallet2::address_book_row data(in_data);

      std::stringstream oss1;
      binary_archive<true> ar1(oss1);
      THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar1, data),
        tools::error::wallet_internal_error, "Failed serialize message");

      addr_row_cipher cipher;
      THROW_WALLET_EXCEPTION_IF(
        !wallet2::encrypt(m_wallet->get_address().m_view_public_key, oss1.str(), cipher.data, cipher.key, cipher.iv),
          tools::error::wallet_internal_error, "Failed encrypt message cipher");

      std::stringstream oss2;
      binary_archive<true> ar2(oss2);
      THROW_WALLET_EXCEPTION_IF(
        !::serialization::serialize(ar2, cipher),
          tools::error::wallet_internal_error, "Failed serialize message");

      lldb::Batch B(m_data, m_idx);

      m_data.put(row_id, {oss2.str().data(), oss2.str().size()});
      m_idx.put(to_salt_hash(addr), row_id);

      B.write();

      std::lock_guard<std::mutex> lock(m_mutex_data);

      m_cache_data[row_id] = data;
      m_cache_idx[addr] = row_id;
      m_cache_order.insert(m_cache_order.begin(), row_id);

      if(m_cache_order.size() > m_cache_limit)
      {
        uint64_t id = m_cache_order.back();
        const auto& it = m_cache_idx.find(address_to_hash(m_cache_data[id].m_address));
        if(it != m_cache_idx.end())
           m_cache_idx.erase(it);
        m_cache_data.erase(m_cache_order.back());
        m_cache_order.pop_back();
      }
      
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return true;
  }

  void adr_db::set_tags(uint64_t row_id, const std::string& tags)
  {
    try
    {
      m_tag.put(row_id, tags.c_str());
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
  }

  bool adr_db::get_tags(uint64_t row_id, std::string& tags)
  {
    try
    {
      lldb::OutVal val;
      if(!m_tag.get(row_id, val))
        return false;
      tags = val.data;
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return true;
  }

  bool adr_db::is_taged(uint64_t row_id, const std::string& tag)
  {
    try
    {
      lldb::OutVal val;
      if(m_tag.get(row_id, val) && std::string::npos != val.data.find(tag))
        return true;
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool adr_db::add_tag(uint64_t row_id, const std::string& tag)
  {
    try
    {
      lldb::OutVal val;
      m_tag.get(row_id, val);
      size_t n = val.data.find(tag);
      if(n == std::string::npos)
      {
        val.data += tag;
        m_tag.put(row_id, val.data.c_str());
        return true;
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool adr_db::del_tag(uint64_t row_id, const std::string& tag)
  {
    try
    {
      lldb::OutVal val;
      if(!m_tag.get(row_id, val))
        return false;
      size_t n = val.data.find(tag);
      if(n != std::string::npos)
      {
        val.data.replace(n, tag.size(), "");
        m_tag.put(row_id, val.data.c_str());
        return true;
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool adr_db::add_tags(uint64_t row_id, const std::vector<std::string>& tags)
  {
    bool rc = false;
    try
    {
      lldb::OutVal val;
      m_tag.get(row_id, val);
      for(auto& tag : tags)
      {
        size_t n = val.data.find(tag);
        if(n == std::string::npos)
        {
          val.data += tag;
          rc = true;
        }
      }
      if(rc)
        m_tag.put(row_id, val.data.c_str());
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return rc;
  }

  bool adr_db::del_tags(uint64_t row_id, const std::vector<std::string>& tags)
  {
    bool rc = false;
    try
    {
      lldb::OutVal val;
      if(!m_tag.get(row_id, val))
        return false;
      for(auto& tag : tags)
      {
        size_t n = val.data.find(tag);
        if(n != std::string::npos)
        {
          val.data.replace(n, tag.size(), "");
          rc = true;
        }
      }
      if(rc)
        m_tag.put(row_id, val.data.c_str());
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return rc;
  }

  void adr_db::add_attr(uint64_t row_id, const std::string& name, const std::string& val)
  {
    try
    {
      lldb::OutVal k;
      k += row_id;
      k += str_to_hash(name);
      m_attr.put(k, val);
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
  }

  bool adr_db::get_attr(uint64_t row_id, const std::string& name, std::string& val)
  {
    try
    {
      lldb::OutVal k;
      k += row_id;
      k += str_to_hash(name);
      lldb::OutVal v;
      if(!m_attr.get(k, v))
        return false;
      val = v.data;
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return true;
  }

  bool adr_db::del_attr(uint64_t row_id, const std::string& name)
  {
    try
    {
      lldb::OutVal k;
      k += row_id;
      k += str_to_hash(name);
      return m_attr.del(k);
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  uint64_t adr_db::size()
  {
    try
    {
      lldb::OutVal key, val;
      if(m_data.last(key, val))
        return key.get<uint64_t>() + 1;
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return 0;
  }

  bool adr_db::get(uint64_t row_id, wallet2::address_book_row& data)
  {
    try
    {
      {
        std::lock_guard<std::mutex> lock(m_mutex_data);
        const auto& it = m_cache_data.find(row_id);
        if(it != m_cache_data.end()) {
          data = it->second;
          return true;
        }
      }

      lldb::OutVal out;
      if(!m_data.get(row_id, out))
        return false;

      binary_archive<false> ar({reinterpret_cast<const std::uint8_t*>(out.data.data()), out.data.size()});
      addr_row_cipher cipher;
      
      THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, cipher),
        tools::error::wallet_internal_error, "Failed parse address row cipher");
      
      std::string data1;
      THROW_WALLET_EXCEPTION_IF(!wallet2::decrypt(cipher.data, cipher.key, cipher.iv, m_wallet->get_account().get_keys().m_view_secret_key, data1),
        tools::error::wallet_internal_error, "Failed decrypt address row cipher");

      binary_archive<false> ar1{epee::strspan<std::uint8_t>(data1)};
      
      THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar1, data),
        tools::error::wallet_internal_error, "Failed parse address row data");

      std::lock_guard<std::mutex> lock2(m_mutex_data);

      m_cache_data[row_id] = data;
      m_cache_idx[address_to_hash(data.m_address)] = row_id;
      m_cache_order.insert(m_cache_order.begin(), row_id);

      if(m_cache_order.size() > m_cache_limit)
      {
        std::lock_guard<std::mutex> lock2(m_mutex_idx);
        uint64_t id = m_cache_order.back();
        const auto& it = m_cache_idx.find(address_to_hash(m_cache_data[id].m_address));
        if(it != m_cache_idx.end())
           m_cache_idx.erase(it);
        m_cache_data.erase(m_cache_order.back());
        m_cache_order.pop_back();
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return true;
  }

  bool adr_db::get_id(const crypto::hash &addr, uint64_t& row_id)
  {
    try
    {
      {
        std::lock_guard<std::mutex> lock(m_mutex_idx);
        const auto& it = m_cache_idx.find(addr);
        if(it != m_cache_idx.end())
        {
          row_id = it->second;
          return true;
        }
      }

      lldb::OutVal val;
      if(m_idx.get(to_salt_hash(addr), val))
      {
        row_id = val.get<uint64_t>();
        m_cache_idx[addr] = row_id;
        return true;
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool adr_db::block(const crypto::hash &addr)
  {
    try
    {
      m_block.put(addr, true);

      return true;
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool adr_db::unblock(const crypto::hash &addr)
  {
    try
    {
      return m_block.del(addr);
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool adr_db::isblock(const crypto::hash &addr)
  {
    try
    {
      lldb::OutVal out;
      if(!m_block.get(addr, out))
        return false;
      return out.get<bool>();
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool adr_db::set(const cryptonote::account_public_address &addr, const wallet2::address_book_row& data) { uint64_t id; return get_id(address_to_hash(addr), id) && set(id, data); }
  bool adr_db::get(const cryptonote::account_public_address &addr, wallet2::address_book_row& data) {  uint64_t id; return get_id(address_to_hash(addr), id) && get(id, data); }

  bool adr_db::set(const crypto::hash &addr, const wallet2::address_book_row& data) { uint64_t id; return get_id(addr, id) && set(id, data); }
  bool adr_db::get(const crypto::hash &addr, wallet2::address_book_row& data) {  uint64_t id; return get_id(addr, id) && get(id, data); }

  bool adr_db::get_id(const cryptonote::account_public_address &addr, uint64_t& row_id) { return get_id(address_to_hash(addr), row_id); }

}
