#include "wallet.h"
#include "message_list.h"
#include "wallet/wallet2.h"

namespace Monero {

    MessageList::~MessageList() {}

    MessageListImpl::MessageListImpl(WalletImpl *wallet)
      : m_wallet(wallet) {}

    MessageListImpl::~MessageListImpl() {}

    bool MessageListImpl::send(const std::string& chat, const std::string& text, uint64_t amount, bool unprunable, uint64_t& n)
    {
        cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            m_errorString = tr("Invalid chat address");
            m_errorCode = Invalid_Address;
            return false;
        }
        return m_wallet->m_wallet->add_message_to_chat(info.address, text, amount, unprunable, n);
    }

    bool MessageListImpl::put(uint64_t& n, const std::string& chat, const std::string& text, const std::string& txid, uint64_t height, uint64_t timestamp)
    {
        cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            m_errorString = tr("Invalid chat address");
            m_errorCode = Invalid_Address;
            return false;
        }
        crypto::hash hash;
        if(!epee::string_tools::hex_to_pod(txid, hash))
        {
            m_errorString = tr("Invalid txid");
            m_errorCode = Invalid_Address;
            return false;
        }
        return m_wallet->m_wallet->db_message_chat_add(n, info.address, m_wallet->m_wallet->get_address(), text, hash, height, timestamp);
    }

    bool MessageListImpl::get(const std::string& chat,
                              uint64_t n,
                              std::string& sender,
                              std::string& text,
                              uint64_t& height,
                              uint64_t& ts,
                              std::string& txid)
    {
        cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            m_errorString = tr("Invalid chat address");
            m_errorCode = Invalid_Address;
            return false;
        }

        tools::wallet2::message_list_row m;
        if(!m_wallet->m_wallet->get_message_from_chat(info.address, n, m))
        {
            m_errorString = tr("Error get message from chat");
            m_errorCode = General_Error;
            return false;
        }

        sender = cryptonote::get_account_address_as_str(m_wallet->m_wallet->nettype(), false, m.m_sender);
        text = m.m_text;
        height = m.m_height;
        ts = m.m_timestamp;
        txid = epee::string_tools::pod_to_hex(m.m_txid);

        return true;
    }

    uint64_t MessageListImpl::getCnt(const std::string& chat)
    {
        cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            m_errorString = tr("Invalid chat address");
            m_errorCode = Invalid_Address;
            return 0;
        }

        tools::wallet2::message_list_row m;
        return m_wallet->m_wallet->get_message_chat_size(info.address);
    }

    uint64_t MessageListImpl::getUnread(const std::string& chat)
    {
        cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            m_errorString = tr("Invalid chat address");
            m_errorCode = Invalid_Address;
            return 0;
        }

        tools::wallet2::message_list_row m;
        return m_wallet->m_wallet->get_message_chat_unread(info.address);
    }

    uint64_t MessageListImpl::getLastTime(const std::string& chat)
    {
        cryptonote::address_parse_info info;
        if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), chat))
        {
            m_errorString = tr("Invalid chat address");
            m_errorCode = Invalid_Address;
            return 0;
        }

        tools::wallet2::message_list_row m;
        return m_wallet->m_wallet->get_message_chat_timestamp(info.address);
    }
}
