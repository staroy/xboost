// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "wallet/api/wallet2_api.h"

namespace Monero {

class WalletImpl;

class AddressBookImpl : public AddressBook
{
public:
    AddressBookImpl(WalletImpl * wallet);
    ~AddressBookImpl();
    
    // Fetches addresses from Wallet2
    bool newMultiUserRow(const std::string& description, const std::string& ab, const std::string& bg, std::function<void(AddressBookRow& row, std::size_t rowId)> callback) override;
    bool addRow(const AddressBookRow& row, std::size_t& rowId) override;
    bool getRow(std::size_t index, std::function<void(AddressBookRow& row)> callback) override;
    bool setDescription(std::size_t index, const std::string &description) override;
    bool setFields(int index, const std::string &address, const std::string &description, const std::string &shortAb, const std::string &backgroundAb) override;
    bool isMultiUser(std::size_t index) override;
    bool deleteRow(std::size_t rowId) override;
    bool undeleteRow(std::size_t rowId) override;
    bool blockRow(std::size_t rowId) override;
    bool unblockRow(std::size_t rowId) override;
    void setTags(std::size_t row_id, const std::string& tags) override;
    bool getTags(std::size_t row_id, std::string& tags) const override;
    bool addTag(std::size_t row_id, const std::string& tag) override;
    bool delTag(std::size_t row_id, const std::string& tag) override;
    bool isTaged(std::size_t row_id, const std::string& tag) override;
    void addAttr(std::size_t row_id, const std::string& name, const std::string& val) override;
    bool getAttr(std::size_t row_id, const std::string& name, std::string& val) const override;
    bool delAttr(std::size_t row_id, const std::string& name) override;
    size_t count() const override;
    void getShortNameBackgroundColorRandomize(std::string& bc) override;
     
    // Error codes. See AddressBook:ErrorCode enum in wallet2_api.h
    std::string errorString() const override {return m_errorString;}
    int errorCode() const override {return m_errorCode;}

    int lookupPaymentID(const std::string &payment_id) const override;
    int lookupAddress(const std::string &addr) const override;
    
private:
    void clearStatus();
    
private:
    WalletImpl *m_wallet;
    std::string m_errorString;
    int m_errorCode;
};

}
