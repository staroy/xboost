#include "wallet/api/wallet2_api.h"

namespace Monero {

class WalletImpl;

class MessageListImpl : public MessageList
{
public:
    MessageListImpl(WalletImpl * wallet);
    ~MessageListImpl();

    bool send(const std::string& chat, const std::string& text, bool enable_comments, uint64_t amount, bool unprunable, uint64_t& n, const std::string& parent = std::string()) override;
    bool put(uint64_t& n, const std::string& chat, const std::string& text, bool enable_comments, const std::string& txid, uint64_t height = 0, uint64_t timestamp = time(NULL), const std::string& parent = std::string()) override;
    bool get(const std::string& chat,
             uint64_t n,
             std::string& sender,
             std::string& text,
             bool& enable_comments,
             uint64_t& height,
             uint64_t& ts,
             std::string& txid) override;
    bool get(const std::string& txid,
             std::string& sender,
             std::string& text,
             bool& enable_comments,
             uint64_t& height,
             uint64_t& ts) override;
    bool getParent(const std::string& chat, std::string& parent) override;
    uint64_t getCnt(const std::string& chat) override;
    uint64_t getUnread(const std::string& chat) override;
    uint64_t getLastTime(const std::string& chat) override;

    // Error codes. See AddressBook:ErrorCode enum in wallet2_api.h
    std::string errorString() const override {return m_errorString;}
    int errorCode() const override {return m_errorCode;}
private:
    WalletImpl *m_wallet;
    std::string m_errorString;
    int m_errorCode;
};

}
