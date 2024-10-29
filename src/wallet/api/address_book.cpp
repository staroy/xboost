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


#include "address_book.h"
#include "wallet.h"
#include "crypto/hash.h"
#include "wallet/wallet2.h"
#include "common_defines.h"

#include <vector>

namespace Monero {
  
AddressBook::~AddressBook() {}
  
AddressBookImpl::AddressBookImpl(WalletImpl *wallet)
    : m_wallet(wallet), m_errorCode(Status_Ok) {}

bool AddressBookImpl::addRow(const AddressBookRow& row)
{
  clearStatus();
  
  cryptonote::address_parse_info info;
  if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), row.getAddress())) {
    m_errorString = tr("Invalid destination address");
    m_errorCode = Invalid_Address;
    return false;
  }

  if (!row.getPaymentId().empty())
  {
    m_errorString = tr("Payment ID supplied: this is obsolete");
    m_errorCode = Invalid_Payment_Id;
    return false;
  }

  tools::wallet2::address_book_row data{
      info.address,
      info.has_payment_id ? info.payment_id : crypto::null_hash8,
      row.getDescription(),
      info.is_subaddress,
      info.has_payment_id,
      info.has_view_skey,
      info.has_view_skey ? info.view_skey : crypto::null_skey,
      "", {}, {}, 0
  };

  bool r =  m_wallet->m_wallet->add_address_book_row(data);
  if (r)
    refresh();
  else
    m_errorCode = General_Error;
  return r;
}

bool AddressBookImpl::setDescription(std::size_t index, const std::string &description)
{
    clearStatus();

    const auto ab = m_wallet->m_wallet->get_address_book();
    if (index >= ab.size()){
        return false;
    }

    tools::wallet2::address_book_row entry = ab[index];
    entry.m_description = description;
    bool r =  m_wallet->m_wallet->set_address_book_row(index, entry);
    if (r)
        refresh();
    else
        m_errorCode = General_Error;
    return r;
}

bool AddressBookImpl::isChannel(std::size_t index)
{
    return m_wallet->m_wallet->is_address_book_row_channel(index);
}

void AddressBookImpl::refresh() 
{
  LOG_PRINT_L2("Refreshing addressbook");
  
  clearRows();
  
  // Fetch from Wallet2 and create vector of AddressBookRow objects
  std::vector<tools::wallet2::address_book_row> rows = m_wallet->m_wallet->get_address_book();
  for (size_t i = 0; i < rows.size(); ++i) {
    tools::wallet2::address_book_row * row = &rows.at(i);
    
    std::string address;
    if (row->m_has_payment_id)
      address = cryptonote::get_account_integrated_address_as_str(m_wallet->m_wallet->nettype(), row->m_address, row->m_payment_id);
    else if (row->m_has_view_skey)
      address = cryptonote::get_account_channel_address_as_str(m_wallet->m_wallet->nettype(), row->m_address.m_spend_public_key, row->m_view_skey);
    else
      address = get_account_address_as_str(m_wallet->m_wallet->nettype(), row->m_is_subaddress, row->m_address);
    AddressBookRow * abr = new AddressBookRow(
                i,
                address,
                "",
                row->m_description,
                row->m_ab,
                "#" + epee::to_hex::string(row->m_ab_color),
                "#" + epee::to_hex::string(row->m_ab_background));
    m_rows.push_back(abr);
  }
  
}

bool AddressBookImpl::deleteRow(std::size_t rowId)
{
  LOG_PRINT_L2("Deleting address book row " << rowId);
  bool r = m_wallet->m_wallet->delete_address_book_row(rowId);
  if (r)
    refresh();
  return r;
} 

int AddressBookImpl::lookupPaymentID(const std::string &payment_id) const
{
    // turn short ones into long ones for comparison
    const std::string long_payment_id = payment_id + std::string(64 - payment_id.size(), '0');

    int idx = -1;
    for (const auto &row: m_rows) {
        ++idx;
        // this does short/short and long/long
        if (payment_id == row->getPaymentId())
            return idx;
        // short/long
        if (long_payment_id == row->getPaymentId())
            return idx;
        // one case left: payment_id was long, row's is short
        const std::string long_row_payment_id = row->getPaymentId() + std::string(64 - row->getPaymentId().size(), '0');
        if (payment_id == long_row_payment_id)
            return idx;
    }
    return -1;
}

void AddressBookImpl::clearRows() {
   for (auto r : m_rows) {
     delete r;
   }
   m_rows.clear();
}

void AddressBookImpl::clearStatus(){
  m_errorString = "";
  m_errorCode = 0;
}

std::vector<AddressBookRow*> AddressBookImpl::getAll() const
{
  return m_rows;
}


AddressBookImpl::~AddressBookImpl()
{
  clearRows();
}

} // namespace
