#include "wallet.h"
#include "message_list.h"
#include "wallet/wallet2.h"

namespace Monero {

    MessageList::~MessageList() {}

    MessageListImpl::MessageListImpl(WalletImpl *wallet)
      : m_wallet(wallet) {}

    MessageListImpl::~MessageListImpl() {}

    bool MessageListImpl::send(const std::string& chat, const std::string& text, bool enable_comments, uint64_t amount, bool unprunable, uint64_t& n, const std::string& parent)
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
            return m_wallet->m_wallet->add_message_to_chat(info.address, text, enable_comments, amount, unprunable, n, parent_hash);
        }

        crypto::hash chat_hash;
        if(!epee::string_tools::hex_to_pod(chat, chat_hash))
        {
            m_errorString = tr("Invalid chat id");
            m_errorCode = Invalid_Address;
            return false;
        }
        return m_wallet->m_wallet->add_message_to_chat(chat_hash, text, enable_comments, amount, unprunable, n, parent_hash);
    }

    bool MessageListImpl::put(uint64_t& n, const std::string& chat, const std::string& text, bool enable_comments, const std::string& txid, uint64_t height, uint64_t timestamp, const std::string& parent)
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
            return m_wallet->m_wallet->db_message_chat_add(n, info.address, m_wallet->m_wallet->get_address(), text, enable_comments, txid_hash, height, timestamp, parent_hash);
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

        return m_wallet->m_wallet->db_message_chat_add(n, chat_hash, addr_hash, text, enable_comments, txid_hash, height, timestamp, parent_hash);
    }

    bool MessageListImpl::get(const std::string& chat,
                              uint64_t n,
                              std::string& sender,
                              std::string& text,
                              bool& enable_comments,
                              uint64_t& height,
                              uint64_t& ts,
                              std::string& txid)
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

        sender = cryptonote::get_account_address_as_str(m_wallet->m_wallet->nettype(), false, m.m_sender);
        text = m.m_text;
        enable_comments = m.m_enable_comments;
        height = m.m_height;
        ts = m.m_timestamp;
        txid = epee::string_tools::pod_to_hex(m.m_txid);

        return true;
    }

    bool MessageListImpl::get(const std::string& txid,
                              std::string& sender,
                              std::string& text,
                              bool& enable_comments,
                              uint64_t& height,
                              uint64_t& ts)
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

        sender = cryptonote::get_account_address_as_str(m_wallet->m_wallet->nettype(), false, m.m_sender);
        text = m.m_text;
        enable_comments = m.m_enable_comments;
        height = m.m_height;
        ts = m.m_timestamp;

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
