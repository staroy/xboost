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

bool AddressBookImpl::newMultiUserRow(const std::string& description, std::function<void(AddressBookRow& row, std::size_t rowId)> callback)
{
  tools::wallet2::address_book_row row; size_t rowId;
  if(!m_wallet->m_wallet->new_multi_user_book_row(description, row, rowId))
    return false;

  std::string address;
  if (row.m_has_payment_id)
    address = cryptonote::get_account_integrated_address_as_str(m_wallet->m_wallet->nettype(), row.m_address, row.m_payment_id);
  else if (row.m_has_view_skey)
    address = cryptonote::get_account_channel_address_as_str(m_wallet->m_wallet->nettype(), row.m_address.m_spend_public_key, row.m_view_skey);
  else
    address = get_account_address_as_str(m_wallet->m_wallet->nettype(), row.m_is_subaddress, row.m_address);

  AddressBookRow Row(address,
            epee::string_tools::pod_to_hex(row.m_payment_id),
            row.m_description,
            row.m_ab,
            "#" + epee::to_hex::string(row.m_ab_color),
            "#" + epee::to_hex::string(row.m_ab_background),
            row.m_has_view_skey,
            row.m_has_spend_skey);

  callback(Row, rowId);
  return true;
}

bool AddressBookImpl::addRow(const AddressBookRow& row, std::size_t& rowId)
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
      false,
      info.has_view_skey,
      crypto::null_skey,
      info.has_view_skey ? info.view_skey : crypto::null_skey,
      "", {}, {}, 0
  };

  if (!m_wallet->m_wallet->add_address_book_row(data, rowId))
  {
    m_errorCode = General_Error;
    return false;
  }
  return true;
}

bool AddressBookImpl::getRow(std::size_t index, std::function<void(AddressBookRow& row)> callback)
{
    tools::wallet2::address_book_row row;
    if(!m_wallet->m_wallet->get_address_book_row(index, row))
       return false;
    
    std::string address;
    if (row.m_has_payment_id)
      address = cryptonote::get_account_integrated_address_as_str(m_wallet->m_wallet->nettype(), row.m_address, row.m_payment_id);
    else if (row.m_has_view_skey)
      address = cryptonote::get_account_channel_address_as_str(m_wallet->m_wallet->nettype(), row.m_address.m_spend_public_key, row.m_view_skey);
    else
      address = get_account_address_as_str(m_wallet->m_wallet->nettype(), row.m_is_subaddress, row.m_address);

    AddressBookRow Row(address,
              epee::string_tools::pod_to_hex(row.m_payment_id),
              row.m_description,
              row.m_ab,
              "#" + epee::to_hex::string(row.m_ab_color),
              "#" + epee::to_hex::string(row.m_ab_background),
              row.m_has_view_skey,
              row.m_has_spend_skey);
    callback(Row);
    return true;
}

bool AddressBookImpl::setDescription(std::size_t index, const std::string &description)
{
    clearStatus();

    if (index >= m_wallet->m_wallet->get_address_book_count())
        return false;

    tools::wallet2::address_book_row entry;
    if(!m_wallet->m_wallet->get_address_book_row(index, entry))
       return false;

    entry.m_description = description;

    if (!m_wallet->m_wallet->set_address_book_row(index, entry))
    {
        m_errorCode = General_Error;
       return false;
    }

    return true;
}

bool AddressBookImpl::isMultiUser(std::size_t index)
{
    return m_wallet->m_wallet->is_address_book_row_multi_user(index);
}

bool AddressBookImpl::deleteRow(std::size_t rowId)
{
  LOG_PRINT_L2("Deleting address book row " << rowId);
  return m_wallet->m_wallet->delete_address_book_row(rowId);
} 

int AddressBookImpl::lookupPaymentID(const std::string &payment_id) const
{
    // turn short ones into long ones for comparison
    const std::string long_payment_id = payment_id + std::string(64 - payment_id.size(), '0');

    for (size_t i = 0; i < m_wallet->m_wallet->get_address_book_count(); ++i)
    {
        tools::wallet2::address_book_row row;
        if (!m_wallet->m_wallet->get_address_book_row(i, row))
            continue;
    
        if (!row.m_has_payment_id)
            continue;

        auto row_payment_id = epee::string_tools::pod_to_hex(row.m_payment_id);

        // this does short/short and long/long
        if (payment_id == row_payment_id)
            return i;
        // short/long
        if (long_payment_id == row_payment_id)
            return i;
        // one case left: payment_id was long, row's is short
        const std::string long_row_payment_id = row_payment_id + std::string(64 - row_payment_id.size(), '0');
        if (payment_id == long_row_payment_id)
            return i;
    }
    return -1;
}

size_t AddressBookImpl::count() const
{
    return m_wallet->m_wallet->get_address_book_count();
}

int AddressBookImpl::lookupAddress(const std::string &addr) const
{
    for (size_t i = 0; i < m_wallet->m_wallet->get_address_book_count(); ++i)
    {
        tools::wallet2::address_book_row row;
        if( !m_wallet->m_wallet->get_address_book_row(i, row) )
            continue;
    
        std::string address;
        if (row.m_has_payment_id)
            address = cryptonote::get_account_integrated_address_as_str(m_wallet->m_wallet->nettype(), row.m_address, row.m_payment_id);
        else if (row.m_has_view_skey)
            address = cryptonote::get_account_channel_address_as_str(m_wallet->m_wallet->nettype(), row.m_address.m_spend_public_key, row.m_view_skey);
        else
            address = get_account_address_as_str(m_wallet->m_wallet->nettype(), row.m_is_subaddress, row.m_address);

        // this does short/short and long/long
        if (addr == address)
            return i;
    }
    return -1;
}

void AddressBookImpl::clearStatus(){
  m_errorString = "";
  m_errorCode = 0;
}

AddressBookImpl::~AddressBookImpl()
{
}

} // namespace
