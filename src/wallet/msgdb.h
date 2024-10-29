
#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include "lldb/lldb.h"
#include "wipeable_string.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace tools
{
  class wallet2;

  class msgdb
  {
  public:
    struct message_data
    {
      crypto::hash chat; // hash address of chat
      crypto::hash sender; // hash address of sender
      uint64_t height; // message height
      uint64_t timestamp; // message timestamp
      std::string data; // text and other

      BEGIN_SERIALIZE_OBJECT()
        VERSION_FIELD(0)
        FIELD(chat)
        FIELD(sender)
        FIELD(height)
        FIELD(timestamp)
        FIELD(data)
      END_SERIALIZE()
    };

    msgdb(const std::string& filename, wallet2 *wallet, uint64_t cache_limit = 100);

    /*
      add message to database,
      return true if success,
      rvalue n assign order position in chat
    */
    bool add(const crypto::hash &txid, const message_data& data, uint64_t& n);

    /*
      set changed message to database,
      return true if success,
      rvalue n assign order position in chat
    */
    bool set(const crypto::hash &txid, const message_data& data);

    /*
      return set timestamp message of tx
      pass chat hash
    */
    bool set_timestamp(const crypto::hash &txid, uint64_t ts);

    /*
      return set height message of tx
      pass chat hash
    */
    bool set_height(const crypto::hash &txid, uint64_t height);

    /*
      get message of chat from database,
      return true if success,
      pass chat hash, n is order position in chat
      assign rvalue message data
    */
    bool get(const crypto::hash &txid, message_data& data);

    /*
      del message from database
      return true if success,
      pass message txid
      assign rvalue message data
    */
    bool del(const crypto::hash& txid);

    /*
      return true if message with txid in database exists
    */
    bool has(const crypto::hash& txid);

    /*
      return count messages in chat
      pass chat hash
    */
    uint64_t size(const crypto::hash &chat);

    /*
      return unread count messages in chat
      pass chat hash
    */
    uint64_t unread(const crypto::hash &chat);

    /*
      return lasttime messages in chat
      pass chat hash
    */
    uint64_t last_timestamp(const crypto::hash &chat);

    /*
      get message id in database,
      return true if success,
      pass chat hash, n is order position in chat
      assign rvalue id of message
    */
    bool get_txid(const crypto::hash &chat, uint64_t n, crypto::hash& txid);

    /*
      get message of chat from database,
      return true if success,
      pass chat address, n is order position in chat
      assign rvalue message data
    */
    bool get(const cryptonote::account_public_address &chat, uint64_t n, message_data& data)
    {
      return get(to_hash(chat), n, data);
    }

    /*
      delete message of chat from database,
      return true if success,
      pass chat address, n is order position in chat
    */
    bool del(const cryptonote::account_public_address &chat, uint64_t n)
    {
      crypto::hash txid; if(!get_txid(chat, n, txid)) return false; return del(txid);
    }

    /*
      return count messages in chat
      pass chat address
    */
    uint64_t size(const cryptonote::account_public_address &chat)
    {
      return size(to_hash(chat));
    }

    /*
      return unread count messages in chat
      pass chat address
    */
    uint64_t unread(const cryptonote::account_public_address &chat)
    {
      return unread(to_hash(chat));
    }

    /*
      return last time messages in chat
      pass chat address
    */
    uint64_t last_timestamp(const cryptonote::account_public_address &chat)
    {
      return last_timestamp(to_hash(chat));
    }

    /*
      get message id in database,
      return true if success,
      pass chat address, n is order position in chat
      assign rvalue id of message
    */
    bool get_txid(const cryptonote::account_public_address &chat, uint64_t n, crypto::hash& txid)
    {
      return get_txid(to_hash(chat), n, txid);
    }

    /*
      get message of chat from database,
      return true if success,
      pass chat hash, n is order position in chat
      assign rvalue message data
    */
    bool get(const crypto::hash &chat, uint64_t n, message_data& data)
    {
      crypto::hash txid; if(!get_txid(chat, n, txid)) return false; return get(txid, data);
    }

    /*
      delete message of chat from database,
      return true if success,
      pass chat hash, n is order position in chat
    */
    bool del(const crypto::hash &chat, uint64_t n)
    {
      crypto::hash txid; if(!get_txid(chat, n, txid)) return false; return del(txid);
    }

    /*
      make hash with internal salt from address
    */
    crypto::hash to_hash(const cryptonote::account_public_address &chat);

  private:
    lldb::DB                                                       m_db,
                                                                   m_data,
                                                                   m_idx,
                                                                   m_last_reading,
                                                                   m_last_timestamp;

    std::unordered_map<crypto::hash, uint64_t>                     m_idx_orders;

    std::unordered_map<crypto::hash, message_data>                 m_cache_data;
    std::unordered_map<crypto::hash, std::vector<crypto::hash>>    m_cache_idx;

    std::vector<crypto::hash>                                      m_cache_order;
    uint64_t                                                       m_cache_limit;

    std::mutex                                                     m_mutex_data,
                                                                   m_mutex_idx,
                                                                   m_mutex_orders;

    crypto::hash                                                   m_salt;
    wallet2                                                       *m_wallet;
  };
}
