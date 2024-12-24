#include <boost/algorithm/string.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/filesystem.hpp>
#include "common/util.h"
#include "misc_log_ex.h"
#include "misc_language.h"
#include "wallet_errors.h"
#include "msg-db.h"
#include "cryptonote_config.h"
#include "wallet2.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.msg_db"

namespace tools
{

  crypto::hash msg_db::to_salt_hash(const crypto::hash &chat)
  {
    crypto::hash hash[] = {chat, m_salt}, res;
    crypto::tree_hash(hash, 2, res);
    return res;
  }

  crypto::hash msg_db::address_to_hash(const cryptonote::account_public_address &chat)
  {
    crypto::hash res;
    crypto::cn_fast_hash(&chat, sizeof(chat), res);
    return res;
  }

  struct message_cipher
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

  msg_db::msg_db(const std::string& filename, wallet2 *wallet, uint64_t cache_limit)
    : m_db(filename)
    , m_data(m_db, "D")
    , m_idx(m_db, "I")
    , m_tags(m_db, "F")
    , m_parent(m_db, "P")
    , m_last_reading(m_db, "R")
    , m_last_timestamp(m_db, "T")
    , m_cache_limit(cache_limit)
    , m_wallet(wallet)
  {
    crypto::cn_fast_hash(m_wallet->get_account().get_keys().m_view_secret_key.data, sizeof(crypto::secret_key), m_salt);
  }

  bool msg_db::add(const crypto::hash &txid, const message_data& in_data, uint64_t& n, const crypto::hash &parent)
  {
    try
    {
      // message with txid exists
      if(has(txid))
        return false;

      message_data data(in_data);
      crypto::hash salt_chat = to_salt_hash(data.chat);

      std::stringstream oss1;
      binary_archive<true> ar1(oss1);
      THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar1, data),
        tools::error::wallet_internal_error, "Failed serialize message");

      message_cipher cipher;
      THROW_WALLET_EXCEPTION_IF(
        !wallet2::encrypt(m_wallet->get_address().m_view_public_key, oss1.str(), cipher.data, cipher.key, cipher.iv),
          tools::error::wallet_internal_error, "Failed encrypt message cipher");

      std::stringstream oss2;
      binary_archive<true> ar2(oss2);
      THROW_WALLET_EXCEPTION_IF(
        !::serialization::serialize(ar2, cipher),
          tools::error::wallet_internal_error, "Failed serialize message");
    
      std::lock_guard<std::mutex> lock(m_mutex_idx);
      auto it = m_cache_idx.find(data.chat);
      if(it == m_cache_idx.end())
      {
        auto& v_idx = m_cache_idx[data.chat];
        lldb::DB S = m_idx.range(salt_chat);
        lldb::OutVal key, val;
        for(bool rc = S.first(key, val); rc; rc = S.next(key, val))
          v_idx.push_back( val.get<crypto::hash>());
      }

      uint64_t order = 0;
      std::lock_guard<std::mutex> lock1(m_mutex_orders);
      auto it1 = m_idx_orders.find(data.chat);
      if(it1 == m_idx_orders.end())
      {
        lldb::DB S = m_idx.range(salt_chat);
        lldb::OutVal key, val;
        if(S.last(key, val))
          order = key.get<uint64_t>() + 1;
        m_idx_orders[data.chat] = order;
      }
      else
      {
        uint64_t& o = it1->second;
        o++; order = o;
      }

      lldb::Batch B(m_data, m_idx, m_parent);

      m_data.put(txid, {oss2.str().data(), oss2.str().size()});
      lldb::OutVal key;
      key += salt_chat;
      key += order;
      m_idx.put(key, txid);

      if(parent != crypto::null_hash)
      {
        lldb::OutVal out;
        if(!m_parent.get(salt_chat, out))
          m_parent.put(salt_chat, parent);
        m_cache_parent[data.chat] = parent;
      }
      else if(data.enable_comments)
      {
        lldb::OutVal key2;
        key2 += to_salt_hash(txid);
        key2 += uint64_t(0);
        m_idx.put(key2, txid);
      }

      B.write();

      {
        lldb::OutVal last_timestamp;
        if(m_last_timestamp.get(salt_chat, last_timestamp))
        {
          if(last_timestamp.get<uint64_t>() < data.timestamp)
            m_last_timestamp.put(salt_chat, data.timestamp);
        }
        else
          m_last_timestamp.put(salt_chat, data.timestamp);
      }

      if(it == m_cache_idx.end())
      {
        auto& v_idx = m_cache_idx[data.chat];
        n = v_idx.size();
        v_idx.push_back(txid);
      }
      else
      {
        n = it->second.size();
        it->second.push_back(txid);
      }

      std::lock_guard<std::mutex> lock2(m_mutex_data);
      m_cache_data[txid] = data;
      m_cache_order.insert(m_cache_order.begin(), txid);
      if(m_cache_order.size() > m_cache_limit)
      {
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

  bool msg_db::set(const crypto::hash &txid, const message_data& in_data)
  {
    try
    {
      // message with txid not exist
      if(!has(txid))
        return false;

      message_data data(in_data);

      std::stringstream oss1;
      binary_archive<true> ar1(oss1);
      THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar1, data),
        tools::error::wallet_internal_error, "Failed serialize message");

      message_cipher cipher;
      THROW_WALLET_EXCEPTION_IF(
        !wallet2::encrypt(m_wallet->get_address().m_view_public_key, oss1.str(), cipher.data, cipher.key, cipher.iv),
          tools::error::wallet_internal_error, "Failed encrypt message cipher");

      std::stringstream oss2;
      binary_archive<true> ar2(oss2);
      THROW_WALLET_EXCEPTION_IF(
        !::serialization::serialize(ar2, cipher),
          tools::error::wallet_internal_error, "Failed serialize message");

      m_data.put(txid, {oss2.str().data(), oss2.str().size()});
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return true;
  }

  bool msg_db::set_timestamp(const crypto::hash &txid, uint64_t ts)
  {
    message_data data;
    if(get(txid, data) && data.timestamp != ts)
    {
      data.timestamp = ts;
      return set(txid, data);
    }
    return false;
  }

  bool msg_db::set_height(const crypto::hash &txid, uint64_t height)
  {
    message_data data;
    if(get(txid, data) && data.height != height)
    {
      data.height = height;
      return set(txid, data);
    }
    return false;
  }

  bool msg_db::get_txid(const crypto::hash &chat, uint64_t n, crypto::hash &txid)
  {
    try
    {
      crypto::hash salt_chat = to_salt_hash(chat);
      lldb::OutVal last_reading;
      if(m_last_reading.get(salt_chat, last_reading)) {
        if(last_reading.get<uint64_t>() < n)
          m_last_reading.put(salt_chat, n);
      } else
        m_last_reading.put(salt_chat, n);
      std::lock_guard<std::mutex> lock(m_mutex_idx);
      auto it = m_cache_idx.find(chat);
      if(it != m_cache_idx.end())
      {
        if(n >= it->second.size())
          return false;
        txid = it->second[n];
        return true;
      }
      else
      {
        auto& v_idx = m_cache_idx[ chat ];
        lldb::DB S = m_idx.range(salt_chat);
        lldb::OutVal key, val;
        for(bool rc = S.first(key, val); rc; rc = S.next(key, val))
          v_idx.push_back( val.get<crypto::hash>() );
        if(n >= v_idx.size())
          return false;
        txid = v_idx[n];
        return true;
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  uint64_t msg_db::size(const crypto::hash &chat)
  {
    try
    {
      std::lock_guard<std::mutex> lock(m_mutex_idx);
      auto it = m_cache_idx.find(chat);
      if(it == m_cache_idx.end())
      {
        auto& v_idx = m_cache_idx[chat];
        lldb::DB S = m_idx.range(to_salt_hash(chat));
        lldb::OutVal key, val;
        for(bool rc = S.first(key, val); rc; rc = S.next(key, val))
          v_idx.push_back( val.get<crypto::hash>() );
        return v_idx.size();
      }
      else
        return it->second.size();
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return 0;
  }

  uint64_t msg_db::unread(const crypto::hash &chat)
  {
    try
    {
      crypto::hash salt_chat = to_salt_hash(chat);
      uint64_t unread = 0;
      uint64_t last_reading = 0;
      lldb::OutVal out;
      if(m_last_reading.get(salt_chat, out))
          last_reading = out.get<uint64_t>();
      std::lock_guard<std::mutex> lock(m_mutex_idx);
      auto it = m_cache_idx.find(chat);
      if(it == m_cache_idx.end())
      {
        auto& v_idx = m_cache_idx[ chat ];
        lldb::DB S = m_idx.range(salt_chat);
        lldb::OutVal key, val;
        for(bool rc = S.first(key, val); rc; rc = S.next(key, val))
          v_idx.push_back( val.get<crypto::hash>() );
        if(v_idx.size() > last_reading)
          unread = v_idx.size() - last_reading - 1;
        else
          unread = 0;
      }
      else
      {
        if(it->second.size() > last_reading)
          unread = it->second.size() - last_reading - 1;
        else
          unread = 0;
      }
      return unread;
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return 0;
  }

  uint64_t msg_db::last_timestamp(const crypto::hash &chat)
  {
    try
    {
      lldb::OutVal last_timestamp;
      if(m_last_timestamp.get(to_salt_hash(chat), last_timestamp))
        return last_timestamp.get<uint64_t>();
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return 0;
  }

  bool msg_db::has(const crypto::hash& txid)
  {
    try
    {
      {
        std::lock_guard<std::mutex> lock2(m_mutex_data);
        const auto& it_data = m_cache_data.find(txid);
        if(it_data != m_cache_data.end())
          return true;
      }

      lldb::OutVal out;
      if(m_data.get(txid, out))
        return true;
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool msg_db::get(const crypto::hash& txid, message_data& data)
  {
    try
    {
      {
        std::lock_guard<std::mutex> lock2(m_mutex_data);
        const auto& it_data = m_cache_data.find(txid);
        if(it_data != m_cache_data.end()) {
          data = it_data->second;
          return true;
        }
      }

      lldb::OutVal out;
      if(!m_data.get(txid, out))
        return false;

      binary_archive<false> ar({reinterpret_cast<const std::uint8_t*>(out.data.data()), out.data.size()});
      message_cipher cipher;
      
      THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, cipher),
        tools::error::wallet_internal_error, "Failed parse message cipher");
      
      std::string data1;
      THROW_WALLET_EXCEPTION_IF(!wallet2::decrypt(cipher.data, cipher.key, cipher.iv, m_wallet->get_account().get_keys().m_view_secret_key, data1),
        tools::error::wallet_internal_error, "Failed decrypt message cipher");

      binary_archive<false> ar1{epee::strspan<std::uint8_t>(data1)};
      
      THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar1, data),
        tools::error::wallet_internal_error, "Failed parse message data");

      std::lock_guard<std::mutex> lock2(m_mutex_data);
      m_cache_data[txid] = data;
      m_cache_order.insert(m_cache_order.begin(), txid);
      if(m_cache_order.size() > m_cache_limit)
      {
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

  bool msg_db::del(const crypto::hash& txid)
  {
    try
    {
      lldb::OutVal out;
      if(!m_data.get(txid, out))
        return false;

      binary_archive<false> ar({reinterpret_cast<const std::uint8_t*>(out.data.data()), out.data.size()});
      message_cipher cipher;
      
      THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, cipher),
        tools::error::wallet_internal_error, "Failed parse message cipher");
      
      std::string data1;
      THROW_WALLET_EXCEPTION_IF(!wallet2::decrypt(cipher.data, cipher.key, cipher.iv, m_wallet->get_account().get_keys().m_view_secret_key, data1),
        tools::error::wallet_internal_error, "Failed decrypt message cipher");

      binary_archive<false> ar1{epee::strspan<std::uint8_t>(data1)};
      
      message_data data;
      THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar1, data),
        tools::error::wallet_internal_error, "Failed parse message data");

      crypto::hash salt_chat = to_salt_hash(data.chat);

      uint64_t order = (uint64_t)-1;
      lldb::DB S = m_idx.range(salt_chat);
      lldb::OutVal key, val;
      for(bool rc = S.first(key, val); rc; rc = S.next(key, val))
        if(txid == val.get<crypto::hash>())
          order = val.get<uint64_t>();


      lldb::Batch B(m_data, m_idx);

      m_data.del(txid);
      lldb::OutVal idx;
      idx += salt_chat;
      idx += order;
      m_idx.del(idx);

      B.write();

      {
        std::lock_guard<std::mutex> lock(m_mutex_idx);
        auto it = m_cache_idx.find(data.chat);
        if(it != m_cache_idx.end()) {
          for(auto i = it->second.begin(); i < it->second.end(); i++)
            if(*i == txid) {
              it->second.erase(i);
              break;
            }
        }
      }

      {
        std::lock_guard<std::mutex> lock2(m_mutex_data);
        const auto& it = m_cache_data.find(txid);
        if(it != m_cache_data.end())
          m_cache_data.erase(it);
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return true;
  }

  bool msg_db::get(const cryptonote::account_public_address &chat, uint64_t n, message_data& data)
  {
    return get(address_to_hash(chat), n, data);
  }

  bool msg_db::del(const cryptonote::account_public_address &chat, uint64_t n)
  {
    return del(address_to_hash(chat), n);
  }

  uint64_t msg_db::size(const cryptonote::account_public_address &chat)
  {
    return size(address_to_hash(chat));
  }

  uint64_t msg_db::unread(const cryptonote::account_public_address &chat)
  {
    return unread(address_to_hash(chat));
  }

  uint64_t msg_db::last_timestamp(const cryptonote::account_public_address &chat)
  {
    return last_timestamp(address_to_hash(chat));
  }

  bool msg_db::get_txid(const cryptonote::account_public_address &chat, uint64_t n, crypto::hash& txid)
  {
    return get_txid(address_to_hash(chat), n, txid);
  }

  bool msg_db::get(const crypto::hash &chat, uint64_t n, message_data& data)
  {
    crypto::hash txid; if(!get_txid(chat, n, txid)) return false; return get(txid, data);
  }

  bool msg_db::del(const crypto::hash &chat, uint64_t n)
  {
    crypto::hash txid; if(!get_txid(chat, n, txid)) return false; return del(txid);
  }

  void msg_db::set_tags(const crypto::hash &txid, const std::string& tags)
  {
    try
    {
      m_tags.put(txid, tags);
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
  }

  bool msg_db::get_tags(const crypto::hash &txid, std::string& tags)
  {
    try
    {
      lldb::OutVal v;
      if(!m_tags.get(txid, v))
        return false;
      tags = v.data;
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return true;
  }

  bool msg_db::add_tag(const crypto::hash &txid, const std::string& tag)
  {
    try
    {
      lldb::OutVal v;
      m_tags.get(txid, v);
      size_t n = v.data.find(tag);
      if(n == std::string::npos)
      {
        v.data += tag;
        m_tags.put(txid, v.data.c_str());
        return true;
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool msg_db::del_tag(const crypto::hash &txid, const std::string& tag)
  {
    try
    {
      lldb::OutVal v;
      if(!m_tags.get(txid, v))
        return false;
      size_t n = v.data.find(tag);
      if(n != std::string::npos)
      {
        v.data.replace(n, tag.size(), "");
        m_tags.put(txid, v.data.c_str());
        return true;
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool msg_db::add_tags(const crypto::hash &txid, const std::vector<std::string>& tags)
  {
    bool rc = false;
    try
    {
      lldb::OutVal v;
      m_tags.get(txid, v);
      for(auto& tag : tags)
      {
        if(v.data.find(tag) == std::string::npos)
        {
          v.data += tag;
          rc = true;
        } 
      }
      if(rc)
        m_tags.put(txid, v.data.c_str());
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return rc;
  }

  bool msg_db::del_tags(const crypto::hash &txid, const std::vector<std::string>& tags)
  {
    bool rc = false;
    try
    {
      lldb::OutVal v;
      if(!m_tags.get(txid, v))
        return false;
      for(auto& tag : tags)
      {
        size_t n = v.data.find(tag);
        if(n != std::string::npos)
        {
          v.data.replace(n, tag.size(), "");
          rc = true;
        }
      }
      if(rc)
        m_tags.put(txid, v.data.c_str());
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
      return false;
    }
    return rc;
  }

  bool msg_db::get_parent(const crypto::hash &chat, crypto::hash &parent)
  {
    try
    {
      crypto::hash salt_chat = to_salt_hash(chat);

      auto it = m_cache_parent.find(chat);
      if(it != m_cache_parent.end())
      {
        parent = it->second;
        return true;
      }

      lldb::OutVal out;
      if(m_parent.get(salt_chat, out))
      {
        parent = out.get<crypto::hash>();
        m_cache_parent[chat] = parent;
        return true;
      }
    }
    catch(const std::exception& e)
    {
      MLOG_RED(el::Level::Error, e.what());
    }
    return false;
  }

  bool msg_db::get_parent(const cryptonote::account_public_address &chat, crypto::hash &parent)
  {
    return get_parent(address_to_hash(chat), parent);
  }

  bool msg_db::set_tags(const crypto::hash &chat, uint64_t n, const std::string& tags)
  {
    crypto::hash txid; if(!get_txid(chat, n, txid)) return false; set_tags(txid, tags); return true;
  }

  bool msg_db::get_tags(const crypto::hash &chat, uint64_t n, std::string& tags)
  {
    crypto::hash txid; if(!get_txid(chat, n, txid)) return false; return get_tags(txid, tags);
  }

  bool msg_db::set_tags(const cryptonote::account_public_address &chat, uint64_t n, const std::string& tags)
  {
    return set_tags(address_to_hash(chat), n, tags);
  }

  bool msg_db::get_tags(const cryptonote::account_public_address &chat, uint64_t n, std::string& tags)
  {
    return get_tags(address_to_hash(chat), n, tags);
  }

  bool msg_db::add_tag(const crypto::hash &chat, uint64_t n, const std::string& tag)
  {
    crypto::hash txid; if(!get_txid(chat, n, txid)) return false; add_tag(txid, tag); return true;
  }

  bool msg_db::del_tag(const crypto::hash &chat, uint64_t n, const std::string& tag)
  {
    crypto::hash txid; if(!get_txid(chat, n, txid)) return false; return del_tag(txid, tag);
  }

  bool msg_db::add_tag(const cryptonote::account_public_address &chat, uint64_t n, const std::string& tag)
  {
    return add_tag(address_to_hash(chat), n, tag);
  }

  bool msg_db::del_tag(const cryptonote::account_public_address &chat, uint64_t n, const std::string& tag)
  {
    return del_tag(address_to_hash(chat), n, tag);
  }

  bool msg_db::add_tags(const crypto::hash &chat, uint64_t n, const std::vector<std::string>& tag)
  {
    crypto::hash txid; if(!get_txid(chat, n, txid)) return false; return add_tags(txid, tag);
  }

  bool msg_db::del_tags(const crypto::hash &chat, uint64_t n, const std::vector<std::string>& tag)
  {
    crypto::hash txid; if(!get_txid(chat, n, txid)) return false; return del_tags(txid, tag);
  }

  bool msg_db::add_tags(const cryptonote::account_public_address &chat, uint64_t n, const std::vector<std::string>& tags)
  {
    return add_tags(address_to_hash(chat), n, tags);
  }

  bool msg_db::del_tags(const cryptonote::account_public_address &chat, uint64_t n, const std::vector<std::string>& tags)
  {
    return del_tags(address_to_hash(chat), n, tags);
  }
}
