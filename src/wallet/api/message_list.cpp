#include "wallet.h"
#include "message_list.h"
#include "wallet/wallet2.h"

namespace Monero {

    MessageList::~MessageList() {}

    MessageListImpl::MessageListImpl(WalletImpl *wallet)
      : m_wallet(wallet) {}

    MessageListImpl::~MessageListImpl() {}

    bool MessageListImpl::send(const std::string& chat,
                               const std::string& text,
                               const std::string& description,
                               const std::string& short_name,
                               bool enable_comments,
                               bool is_anon,
                               uint64_t amount,
                               bool unprunable,
                               uint64_t& n,
                               const std::string& parent)
    {
        crypto::hash parent_hash = crypto::null_hash;
        if(!parent.empty())
        {
            cryptonote::address_parse_info info;
            if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), parent))
            {
                if(!epee::string_tools::hex_to_pod(parent, parent_hash))
                {
                    m_errorString = tr("Invalid parent hex data");
                    m_errorCode = Invalid_Address;
                    return false;
                }
            }
            else
                crypto::cn_fast_hash(&info.address, sizeof(info.address), parent_hash);
        }

        cryptonote::address_parse_info info;
        if(cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            return m_wallet->m_wallet->add_message_to_chat(info.address, text, description, short_name, enable_comments, is_anon, amount, unprunable, n, parent_hash);
        }

        crypto::hash chat_hash;
        if(!epee::string_tools::hex_to_pod(chat, chat_hash))
        {
            m_errorString = tr("Invalid chat id");
            m_errorCode = Invalid_Address;
            return false;
        }
        return m_wallet->m_wallet->add_message_to_chat(chat_hash, text, description, short_name, enable_comments, is_anon, amount, unprunable, n, parent_hash);
    }

    bool MessageListImpl::put(uint64_t& n,
                              const std::string& chat,
                              const std::string& text,
                              const std::string& description,
                              const std::string& short_name,
                              bool enable_comments,
                              const std::string& txid,
                              uint64_t height,
                              uint64_t timestamp,
                              const std::string& parent)
    {
        crypto::hash parent_hash = crypto::null_hash;
        if(!parent.empty())
        {
            cryptonote::address_parse_info info;
            if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), parent))
            {
                if(!epee::string_tools::hex_to_pod(parent, parent_hash))
                {
                    m_errorString = tr("Invalid parent hex data");
                    m_errorCode = Invalid_Address;
                    return false;
                }
            }
            else
                crypto::cn_fast_hash(&info.address, sizeof(info.address), parent_hash);
        }

        crypto::hash txid_hash;
        if(!epee::string_tools::hex_to_pod(txid, txid_hash))
        {
            m_errorString = tr("Invalid txid");
            m_errorCode = Invalid_Address;
            return false;
        }

        cryptonote::address_parse_info info;
        if(cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            return m_wallet->m_wallet->db_message_chat_add(n, info.address, m_wallet->m_wallet->get_address(), text, description, short_name, enable_comments, txid_hash, height, timestamp, parent_hash);
        }

        crypto::hash chat_hash;
        if(!epee::string_tools::hex_to_pod(chat, chat_hash))
        {
            m_errorString = tr("Invalid chat id");
            m_errorCode = Invalid_Address;
            return false;
        }

        crypto::hash addr_hash;
        cryptonote::account_public_address addr = m_wallet->m_wallet->get_address();
        crypto::cn_fast_hash(&addr, sizeof(addr), addr_hash);

        return m_wallet->m_wallet->db_message_chat_add(n, chat_hash, addr_hash, text, description, short_name, enable_comments, txid_hash, height, timestamp, parent_hash);
    }

    bool MessageListImpl::get(const std::string& chat,
                              uint64_t n,
                              std::string& sender,
                              uint64_t& sender_rowid,
                              std::string& text,
                              std::string& description,
                              std::string& short_name,
                              bool& enable_comments,
                              uint64_t& height,
                              uint64_t& ts,
                              std::string& txid,
                              std::string& tags)
    {
        crypto::hash chat_hash;  cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid parent hex data");
                m_errorCode = Invalid_Address;
                return false;
            }
        }
        else
            crypto::cn_fast_hash(&info.address, sizeof(info.address), chat_hash);

        tools::wallet2::message_list_row m;
        if(!m_wallet->m_wallet->get_message_from_chat(chat_hash, n, m))
        {
            m_errorString = tr("Error get message from chat");
            m_errorCode = General_Error;
            return false;
        }

        m_wallet->m_wallet->get_message_chat_tags(chat_hash, n, tags);

        if(m.m_sender.m_spend_public_key != crypto::null_pkey && m.m_sender.m_view_public_key != crypto::null_pkey)
        {
          m_wallet->m_wallet->get_address_book_row_id(m.m_sender, sender_rowid);
          sender = cryptonote::get_account_address_as_str(m_wallet->m_wallet->nettype(), false, m.m_sender);
        }
        else
        {
          sender_rowid = (uint64_t)-1;
          sender = epee::string_tools::pod_to_hex(m.m_sender_hash);
        }
        text = m.m_text;
        description = m.m_description;
        short_name = m.m_short_name;
        enable_comments = m.m_enable_comments;
        height = m.m_height;
        ts = m.m_timestamp;
        txid = epee::string_tools::pod_to_hex(m.m_txid);

        return true;
    }

    bool MessageListImpl::get(const std::string& txid,
                              std::string& sender,
                              uint64_t& sender_rowid,
                              std::string& text,
                              std::string& description,
                              std::string& short_name,
                              bool& enable_comments,
                              uint64_t& height,
                              uint64_t& ts,
                              std::string& tags)
    {
        crypto::hash txid_hash;
        if(!epee::string_tools::hex_to_pod(txid, txid_hash))
        {
            m_errorString = tr("Invalid txid hex data");
            m_errorCode = Invalid_Address;
            return false;
        }

        tools::wallet2::message_list_row m;
        if(!m_wallet->m_wallet->get_message_from_txid(txid_hash, m))
        {
            m_errorString = tr("Error get message from txid");
            m_errorCode = General_Error;
            return false;
        }

        m_wallet->m_wallet->get_message_chat_tags(txid_hash, tags);

        if(m.m_sender.m_spend_public_key != crypto::null_pkey && m.m_sender.m_view_public_key != crypto::null_pkey)
        {
          m_wallet->m_wallet->get_address_book_row_id(m.m_sender, sender_rowid);
          sender = cryptonote::get_account_address_as_str(m_wallet->m_wallet->nettype(), false, m.m_sender);
        }
        else
        {
          sender_rowid = (uint64_t)-1;
          sender = epee::string_tools::pod_to_hex(m.m_sender_hash);
        }
        text = m.m_text;
        description = m.m_description;
        short_name = m.m_short_name;
        enable_comments = m.m_enable_comments;
        height = m.m_height;
        ts = m.m_timestamp;

        return true;
    }

    bool MessageListImpl::del(const std::string& chat, uint64_t n)
    {
        crypto::hash chat_hash;  cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid parent hex data");
                m_errorCode = Invalid_Address;
                return false;
            }
        }
        else
            crypto::cn_fast_hash(&info.address, sizeof(info.address), chat_hash);

        return m_wallet->m_wallet->del_message_chat_row(chat_hash, n);
    }

    bool MessageListImpl::undel(const std::string& chat, uint64_t n)
    {
        crypto::hash chat_hash;  cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid parent hex data");
                m_errorCode = Invalid_Address;
                return false;
            }
        }
        else
            crypto::cn_fast_hash(&info.address, sizeof(info.address), chat_hash);

        return m_wallet->m_wallet->undel_message_chat_row(chat_hash, n);
    }

    bool MessageListImpl::setTags(const std::string& chat, uint64_t n, const std::string& tags)
    {
        crypto::hash chat_hash;  cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid chat hex data");
                m_errorCode = Invalid_Address;
                return false;
            }
        }
        else
            crypto::cn_fast_hash(&info.address, sizeof(info.address), chat_hash);

        m_wallet->m_wallet->set_message_chat_tags(chat_hash, n, tags);

        return true;
    }

    bool MessageListImpl::getTags(const std::string& chat, uint64_t n, std::string& tags)
    {
        crypto::hash chat_hash;  cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid chat hex data");
                m_errorCode = Invalid_Address;
                return false;
            }
        }
        else
            crypto::cn_fast_hash(&info.address, sizeof(info.address), chat_hash);

        tools::wallet2::message_list_row m;
        if(!m_wallet->m_wallet->get_message_chat_tags(chat_hash, n, tags))
        {
            m_errorString = tr("Error get message chat tags");
            m_errorCode = General_Error;
            return false;
        }
        return true;
    }

    bool MessageListImpl::setTags(const std::string& txid, const std::string& tags)
    {
        crypto::hash txid_hash;
        if(!epee::string_tools::hex_to_pod(txid, txid_hash))
        {
            m_errorString = tr("Invalid txid hex data");
            m_errorCode = Invalid_Address;
            return false;
        }

        tools::wallet2::message_list_row m;
        m_wallet->m_wallet->set_message_chat_tags(txid_hash, tags);

        return true;
    }

    bool MessageListImpl::getTags(const std::string& txid, std::string& tags)
    {
        crypto::hash txid_hash;
        if(!epee::string_tools::hex_to_pod(txid, txid_hash))
        {
            m_errorString = tr("Invalid txid hex data");
            m_errorCode = Invalid_Address;
            return false;
        }

        tools::wallet2::message_list_row m;
        if(!m_wallet->m_wallet->get_message_chat_tags(txid_hash, tags))
        {
            m_errorString = tr("Error set message chat tags");
            m_errorCode = General_Error;
            return false;
        }
        return true;
    }

    bool MessageListImpl::addTag(const std::string& chat, uint64_t n, const std::string& tag)
    {
        crypto::hash chat_hash;  cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid chat hex data");
                m_errorCode = Invalid_Address;
                return false;
            }
        }
        else
            crypto::cn_fast_hash(&info.address, sizeof(info.address), chat_hash);

        if(!m_wallet->m_wallet->add_message_chat_tag(chat_hash, n, tag))
        {
            m_errorString = tr("Error add message chat tag");
            m_errorCode = General_Error;
            return false;
        }
        return true;
    }

    bool MessageListImpl::delTag(const std::string& chat, uint64_t n, const std::string& tag)
    {
        crypto::hash chat_hash;  cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid chat hex data");
                m_errorCode = Invalid_Address;
                return false;
            }
        }
        else
            crypto::cn_fast_hash(&info.address, sizeof(info.address), chat_hash);

        tools::wallet2::message_list_row m;
        if(!m_wallet->m_wallet->del_message_chat_tag(chat_hash, n, tag))
        {
            m_errorString = tr("Error get message chat tags");
            m_errorCode = General_Error;
            return false;
        }
        return true;
    }

    bool MessageListImpl::addTag(const std::string& txid, const std::string& tag)
    {
        crypto::hash txid_hash;
        if(!epee::string_tools::hex_to_pod(txid, txid_hash))
        {
            m_errorString = tr("Invalid txid hex data");
            m_errorCode = Invalid_Address;
            return false;
        }

        tools::wallet2::message_list_row m;
        if(!m_wallet->m_wallet->add_message_chat_tag(txid_hash, tag))
        {
            m_errorString = tr("Error add message chat tag");
            m_errorCode = General_Error;
            return false;
        }
        return true;

    }

    bool MessageListImpl::delTag(const std::string& txid, const std::string& tag)
    {
        crypto::hash txid_hash;
        if(!epee::string_tools::hex_to_pod(txid, txid_hash))
        {
            m_errorString = tr("Invalid txid hex data");
            m_errorCode = Invalid_Address;
            return false;
        }

        tools::wallet2::message_list_row m;
        if(!m_wallet->m_wallet->del_message_chat_tag(txid_hash, tag))
        {
            m_errorString = tr("Error del message chat tag");
            m_errorCode = General_Error;
            return false;
        }
        return true;
    }

    bool MessageListImpl::getParent(const std::string& chat, std::string& parent)
    {
        bool r = false;
        crypto::hash parent_hash;

        cryptonote::address_parse_info info;
        if(cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            r = m_wallet->m_wallet->get_message_chat_parent(info.address, parent_hash);
        }

        if(!r)
        {
            crypto::hash chat_hash;
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid chat id");
                m_errorCode = Invalid_Address;
                return false;
            }
            r = m_wallet->m_wallet->get_message_chat_parent(chat_hash, parent_hash);
        }

        if(r)
        {
            parent = epee::string_tools::pod_to_hex(parent_hash);
        }
        return r;
    }

    uint64_t MessageListImpl::getCnt(const std::string& chat)
    {
        crypto::hash chat_hash;  cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid parent hex data");
                m_errorCode = Invalid_Address;
                return false;
            }
        }
        else
            crypto::cn_fast_hash(&info.address, sizeof(info.address), chat_hash);

        return m_wallet->m_wallet->get_message_chat_size(chat_hash);
    }

    uint64_t MessageListImpl::getUnread(const std::string& chat)
    {
        crypto::hash chat_hash;  cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid parent hex data");
                m_errorCode = Invalid_Address;
                return false;
            }
        }
        else
            crypto::cn_fast_hash(&info.address, sizeof(info.address), chat_hash);

        return m_wallet->m_wallet->get_message_chat_unread(chat_hash);
    }

    uint64_t MessageListImpl::getLastTime(const std::string& chat)
    {
        crypto::hash chat_hash;  cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            if(!epee::string_tools::hex_to_pod(chat, chat_hash))
            {
                m_errorString = tr("Invalid parent hex data");
                m_errorCode = Invalid_Address;
                return false;
            }
        }
        else
            crypto::cn_fast_hash(&info.address, sizeof(info.address), chat_hash);

        return m_wallet->m_wallet->get_message_chat_timestamp(chat_hash);
    }
}
