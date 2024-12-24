
#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include "lldb/lldb.h"
#include "wipeable_string.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "wallet2.h"

namespace tools
{
  class adr_db
  {
  public:

    adr_db(const std::string& filename, wallet2 *wallet, uint64_t cache_limit = 100);

    bool add(const wallet2::address_book_row& data, uint64_t& row_id);

    bool set(uint64_t row_id, const wallet2::address_book_row& data);
    bool get(uint64_t row_id, wallet2::address_book_row& data);

    void set_tags(uint64_t row_id, const std::string& tags);
    bool get_tags(uint64_t row_id, std::string& tags);
    bool add_tag(uint64_t row_id, const std::string& tag);
    bool del_tag(uint64_t row_id, const std::string& tag);
    bool add_tags(uint64_t row_id, const std::vector<std::string>& tag);
    bool del_tags(uint64_t row_id, const std::vector<std::string>& tag);
    bool is_taged(uint64_t row_id, const std::string& tag);

    void add_attr(uint64_t row_id, const std::string& name, const std::string& val);
    bool get_attr(uint64_t row_id, const std::string& name, std::string& val);
    bool del_attr(uint64_t row_id, const std::string& name);

    uint64_t size();

    bool set(const cryptonote::account_public_address &addr, const wallet2::address_book_row& data);
    bool get(const cryptonote::account_public_address &addr, wallet2::address_book_row& data);

    bool set(const crypto::hash &addr, const wallet2::address_book_row& data);
    bool get(const crypto::hash &addr, wallet2::address_book_row& data);

    bool get_id(const cryptonote::account_public_address &addr, uint64_t& row_id);
    bool get_id(const crypto::hash &addr, uint64_t& row_id);

    bool block(const crypto::hash &addr);
    bool unblock(const crypto::hash &addr);
    bool isblock(const crypto::hash &addr);

    /*
      get row id from hash with internal salt
    */
    bool get_row_id(const crypto::hash &interal_hash, uint64_t& row_id);


  private:
    /*
      make hash with internal salt
    */
    crypto::hash to_salt_hash(const crypto::hash &addr);
    crypto::hash address_to_hash(const cryptonote::account_public_address &chat);


    lldb::DB                                                       m_db,
                                                                   m_data,
                                                                   m_chat,
                                                                   m_tag,
                                                                   m_attr,
                                                                   m_block,
                                                                   m_idx;

    std::unordered_map<uint64_t, wallet2::address_book_row>        m_cache_data;
    std::unordered_map<crypto::hash, uint64_t>                     m_cache_idx;
    std::vector<uint64_t>                                          m_cache_order;
    uint64_t                                                       m_cache_limit;

    std::mutex                                                     m_mutex_idx,
                                                                   m_mutex_data;

    crypto::hash                                                   m_salt;
    wallet2                                                       *m_wallet;
  };
}
