
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

  class msg_db
  {
  public:
    struct message_data
    {
      crypto::hash chat; // hash address of chat
      crypto::hash sender; // hash address of sender
      uint64_t height; // message height
      uint64_t timestamp; // message timestamp
      std::string data; // text and other
      std::string description; // description
      std::string short_name; // short name
      bool enable_comments;

      BEGIN_SERIALIZE_OBJECT()
        VERSION_FIELD(0)
        FIELD(chat)
        FIELD(sender)
        FIELD(height)
        FIELD(timestamp)
        FIELD(data)
        FIELD(description)
        FIELD(short_name)
        FIELD(enable_comments)
      END_SERIALIZE()
    };

    msg_db(const std::string& filename, wallet2 *wallet, uint64_t cache_limit = 100);

    /*
      add message to database,
      return true if success,
      rvalue n assign order position in chat
    */
    bool add(const crypto::hash &txid, const message_data& data, uint64_t& n, const crypto::hash &parent = crypto::null_hash);

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
      set changed tags to database,
      return true if success,
    */
    void set_tags(const crypto::hash &txid, const std::string& tags);

    /*
      get tags of chat from database,
      return true if success,
      assign rvalue message tags
    */
    bool get_tags(const crypto::hash &txid, std::string& tags);

    /*
      add tag to database,
      return true if success,
    */
    bool add_tag(const crypto::hash &txid, const std::string& tag);

    /*
      del tag of chat from database,
      return true if success,
      assign rvalue message tags
    */
    bool del_tag(const crypto::hash &txid, const std::string& tag);

    /*
      add tag to database,
      return true if success,
    */
    bool add_tags(const crypto::hash &txid, const std::vector<std::string>& tags);

    /*
      del tag of chat from database,
      return true if success,
      assign rvalue message tags
    */
    bool del_tags(const crypto::hash &txid, const std::vector<std::string>& tags);

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
    bool get(const cryptonote::account_public_address &chat, uint64_t n, message_data& data);

    /*
      delete message of chat from database,
      return true if success,
      pass chat address, n is order position in chat
    */
    bool del(const cryptonote::account_public_address &chat, uint64_t n);

    /*
      return count messages in chat
      pass chat address
    */
    uint64_t size(const cryptonote::account_public_address &chat);

    /*
      return unread count messages in chat
      pass chat address
    */
 
    uint64_t unread(const cryptonote::account_public_address &chat);

    /*
      return last time messages in chat
      pass chat address
    */
    uint64_t last_timestamp(const cryptonote::account_public_address &chat);

    /*
      get message id in database,
      return true if success,
      pass chat address, n is order position in chat
      assign rvalue id of message
    */
    bool get_txid(const cryptonote::account_public_address &chat, uint64_t n, crypto::hash& txid);

    /*
      get message of chat from database,
      return true if success,
      pass chat hash, n is order position in chat
      assign rvalue message data
    */
    bool get(const crypto::hash &chat, uint64_t n, message_data& data);

    /*
      delete message of chat from database,
      return true if success,
      pass chat hash, n is order position in chat
    */
    bool del(const crypto::hash &chat, uint64_t n);

    /*
      get parent chat of chat
      return true if success,
      pass chat hash
      assign rvalue parent
    */
    bool get_parent(const crypto::hash &chat, crypto::hash &parent);

    /*
      get parent chat of chat
      return true if success,
      pass chat hash
      assign rvalue parent
    */
    bool get_parent(const cryptonote::account_public_address &chat, crypto::hash &parent);

    /*
      set changed tags to database,
      return true if success,
    */
    bool set_tags(const crypto::hash &chat, uint64_t n, const std::string& tags);

    /*
      get tags of chat from database,
      return true if success,
      assign rvalue message tags
    */
    bool get_tags(const crypto::hash &chat, uint64_t n, std::string& tags);

    /*
      add tags to database,
      return true if success,
    */
    bool add_tag(const crypto::hash &chat, uint64_t n, const std::string& tag);

    /*
      get tags of chat from database,
      return true if success,
      assign rvalue message tags
    */
    bool del_tag(const crypto::hash &chat, uint64_t n, const std::string& tag);

    /*
      set changed tags to database,
      return true if success,
    */
    bool set_tags(const cryptonote::account_public_address &chat, uint64_t n, const std::string& tags);

    /*
      get tags of chat from database,
      return true if success,
      assign rvalue message tags
    */
    bool get_tags(const cryptonote::account_public_address &chat, uint64_t n, std::string& tags);

    /*
      add tag to database,
      return true if success,
    */
    bool add_tag(const cryptonote::account_public_address &chat, uint64_t n, const std::string& tag);

    /*
      del tag of chat from database,
      return true if success,
      assign rvalue message tags
    */
    bool del_tag(const cryptonote::account_public_address &chat, uint64_t n, const std::string& tags);

    /*
      add tags to database,
      return true if success,
    */
    bool add_tags(const crypto::hash &chat, uint64_t n, const std::vector<std::string>& tags);

    /*
      del tag of chat from database,
      return true if success,
      assign rvalue message tags
    */
    bool del_tags(const crypto::hash &chat, uint64_t n, const std::vector<std::string>& tags);

    /*
      adds tag to database,
      return true if success,
    */
    bool add_tags(const cryptonote::account_public_address &chat, uint64_t n, const std::vector<std::string>& tags);

    /*
      del tags of chat from database,
      return true if success,
      assign rvalue message tags
    */
    bool del_tags(const cryptonote::account_public_address &chat, uint64_t n, const std::vector<std::string>& tags);

  private:

    crypto::hash to_salt_hash(const crypto::hash &chat);
    crypto::hash address_to_hash(const cryptonote::account_public_address &chat);

    lldb::DB                                                       m_db,
                                                                   m_data,
                                                                   m_idx,
                                                                   m_tags,
                                                                   m_parent,
                                                                   m_last_reading,
                                                                   m_last_timestamp;

    std::unordered_map<crypto::hash, uint64_t>                     m_idx_orders;

    std::unordered_map<crypto::hash, message_data>                 m_cache_data;
    std::unordered_map<crypto::hash, std::vector<crypto::hash>>    m_cache_idx;
    std::unordered_map<crypto::hash, crypto::hash>                 m_cache_parent;

    std::vector<crypto::hash>                                      m_cache_order;
    uint64_t                                                       m_cache_limit;

    std::mutex                                                     m_mutex_data,
                                                                   m_mutex_idx,
                                                                   m_mutex_orders;

    crypto::hash                                                   m_salt;
    wallet2                                                       *m_wallet;
  };
}
