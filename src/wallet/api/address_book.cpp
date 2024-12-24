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

bool AddressBookImpl::newMultiUserRow(const std::string& description, const std::string& ab, const std::string& bg, std::function<void(AddressBookRow& row, std::size_t rowId)> callback)
{
  std::vector<uint8_t> bc(3);
  if(!epee::from_hex::to_buffer({bc.data(), bc.size()}, bg.substr(1)))
    return false;

  tools::wallet2::address_book_row row; size_t rowId;
  if(!m_wallet->m_wallet->new_multi_user_book_row(description, ab, bc, row, rowId))
    return false;

  std::string address;
  if (row.m_has_payment_id)
    address = cryptonote::get_account_integrated_address_as_str(m_wallet->m_wallet->nettype(), row.m_address, row.m_payment_id);
  else if (row.m_has_view_skey)
    address = cryptonote::get_account_channel_address_as_str(m_wallet->m_wallet->nettype(), row.m_address.m_spend_public_key, row.m_view_skey);
  else
    address = cryptonote::get_account_address_as_str(m_wallet->m_wallet->nettype(), row.m_is_subaddress, row.m_address);

  AddressBookRow Row(address,
            row.m_payment_id == crypto::null_hash8 ? "" : epee::string_tools::pod_to_hex(row.m_payment_id),
            row.m_description,
            row.m_short_name,
            "#" + epee::to_hex::string(row.m_short_name_color),
            "#" + epee::to_hex::string(row.m_short_name_background),
            row.m_has_view_skey,
            row.m_has_spend_skey);

  callback(Row, rowId);
  return true;
}

bool AddressBookImpl::addRow(const AddressBookRow& row, std::size_t& rowId)
{
  clearStatus();
  
  cryptonote::address_parse_info info;
  crypto::hash address_hash = crypto::null_hash;
  if(!cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), row.getAddress()))
  {
    info.address.m_spend_public_key = crypto::null_pkey;
    info.address.m_view_public_key = crypto::null_pkey;
    if(!epee::string_tools::hex_to_pod(row.getAddress(), address_hash))
    {
      m_errorString = tr("Invalid destination address");
      m_errorCode = Invalid_Address;
      return false;
    }
  }

  if (!row.getPaymentId().empty())
  {
    m_errorString = tr("Payment ID supplied: this is obsolete");
    m_errorCode = Invalid_Payment_Id;
    return false;
  }

  tools::wallet2::address_book_row data{
      info.address,
      address_hash,
      info.has_payment_id ? info.payment_id : crypto::null_hash8,
      row.getDescription(),
      info.is_subaddress,
      info.has_payment_id,
      false,
      info.has_view_skey,
      crypto::null_skey,
      info.has_view_skey ? info.view_skey : crypto::null_skey,
      row.getShortName(),
      {},
      {},
      0,
      row.getMyDescription(),
      row.getMyShortName()
  };

  epee::from_hex::to_buffer(data.m_short_name_color, row.getShortNameColor().substr(1));
  epee::from_hex::to_buffer(data.m_short_name_background, row.getShortNameBackground().substr(1));

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
    bool is_anon = row.m_address.m_spend_public_key == crypto::null_pkey || row.m_address.m_view_public_key == crypto::null_pkey;
    if(!is_anon)
    {  
      if (row.m_has_payment_id)
        address = cryptonote::get_account_integrated_address_as_str(m_wallet->m_wallet->nettype(), row.m_address, row.m_payment_id);
      else if (row.m_has_view_skey)
        address = cryptonote::get_account_channel_address_as_str(m_wallet->m_wallet->nettype(), row.m_address.m_spend_public_key, row.m_view_skey);
      else
        address = get_account_address_as_str(m_wallet->m_wallet->nettype(), row.m_is_subaddress, row.m_address);
    }
    else
        address = epee::string_tools::pod_to_hex(row.m_address_hash);

    AddressBookRow Row(address,
              row.m_payment_id == crypto::null_hash8 ? "" : epee::string_tools::pod_to_hex(row.m_payment_id),
              row.m_description,
              row.m_short_name,
              "#" + epee::to_hex::string(row.m_short_name_color),
              "#" + epee::to_hex::string(row.m_short_name_background),
              row.m_has_view_skey,
              row.m_has_spend_skey,
              row.m_my_description,
              row.m_my_short_name);
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

bool AddressBookImpl::setFields(int index, const std::string &address, const std::string &description, const std::string &shortName, const std::string &shortNameBackground)
{
    clearStatus();

    if (index >= m_wallet->m_wallet->get_address_book_count())
        return false;

    tools::wallet2::address_book_row entry;
    if(!m_wallet->m_wallet->get_address_book_row(index, entry))
       return false;

    bool is_anon = entry.m_address.m_spend_public_key == crypto::null_pkey || entry.m_address.m_view_public_key == crypto::null_pkey;

    cryptonote::address_parse_info info;
    if(is_anon && !address.empty() && cryptonote::get_account_address_from_str(info, m_wallet->m_wallet->nettype(), address))
    {
      if(entry.m_address_hash != tools::address_to_hash(info.address))
      {
        m_errorString = tr("Invalid destination address");
        m_errorCode = Invalid_Address;
        return false;
      }
      entry.m_address = info.address;
      is_anon = false;
    }

    entry.m_description = description;
    entry.m_short_name = shortName;

    if(!epee::from_hex::to_buffer(entry.m_short_name_background, shortNameBackground.substr(1)))
       return false;

    if(0.3*entry.m_short_name_background[0]+0.59*entry.m_short_name_background[1]+0.11*entry.m_short_name_background[2] > 128.0)
    {                
      entry.m_short_name_color[0] = 0x30;
      entry.m_short_name_color[1] = 0x30;
      entry.m_short_name_color[2] = 0x30;
    }
    else
    {
      entry.m_short_name_color[0] = 0xf0;
      entry.m_short_name_color[1] = 0xf0;
      entry.m_short_name_color[2] = 0xf0;
    }

    if (!m_wallet->m_wallet->set_address_book_row(index, entry))
    {
       m_errorCode = General_Error;
       return false;
    }

    if(!is_anon && !address.empty())
      m_wallet->m_wallet->del_address_book_tag(index, Monero::TAG_ANON);

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

bool AddressBookImpl::undeleteRow(std::size_t rowId)
{
  LOG_PRINT_L2("Deleting address book row " << rowId);
  return m_wallet->m_wallet->undelete_address_book_row(rowId);
} 

bool AddressBookImpl::blockRow(std::size_t rowId)
{
  LOG_PRINT_L2("Deleting address book row " << rowId);
  return m_wallet->m_wallet->block_address_book_row(rowId);
} 

bool AddressBookImpl::unblockRow(std::size_t rowId)
{
  LOG_PRINT_L2("Deleting address book row " << rowId);
  return m_wallet->m_wallet->unblock_address_book_row(rowId);
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

void AddressBookImpl::setTags(std::size_t row_id, const std::string& tags)
{
    m_wallet->m_wallet->set_address_book_tags(row_id, tags);
}

bool AddressBookImpl::getTags(std::size_t row_id, std::string& tags) const
{
    return m_wallet->m_wallet->get_address_book_tags(row_id, tags);
}

bool AddressBookImpl::isTaged(std::size_t row_id, const std::string& tag)
{
    return m_wallet->m_wallet->is_address_book_taged(row_id, tag);
}

bool AddressBookImpl::addTag(std::size_t row_id, const std::string& tag)
{
    return m_wallet->m_wallet->add_address_book_tag(row_id, tag);
}

bool AddressBookImpl::delTag(std::size_t row_id, const std::string& tag)
{
    return m_wallet->m_wallet->del_address_book_tag(row_id, tag);
}

void AddressBookImpl::addAttr(std::size_t row_id, const std::string& name, const std::string& val)
{
    m_wallet->m_wallet->add_address_book_attr(row_id, name, val);
}

bool AddressBookImpl::getAttr(std::size_t row_id, const std::string& name, std::string& val) const
{
    return m_wallet->m_wallet->get_address_book_attr(row_id, name, val);
}

bool AddressBookImpl::delAttr(std::size_t row_id, const std::string& name)
{
    return m_wallet->m_wallet->del_address_book_attr(row_id, name);
}

size_t AddressBookImpl::count() const
{
    return m_wallet->m_wallet->get_address_book_count();
}

void AddressBookImpl::getShortNameBackgroundColorRandomize(std::string& bc)
{
    std::vector<uint8_t> c;
    m_wallet->m_wallet->get_short_name_background_color_randomize(c);
    bc = "#" + epee::to_hex::string({c.data(), c.size()});
}

int AddressBookImpl::lookupAddress(const std::string &addr) const
{
    for (size_t i = 0; i < m_wallet->m_wallet->get_address_book_count(); ++i)
    {
        tools::wallet2::address_book_row row;
        if( !m_wallet->m_wallet->get_address_book_row(i, row) )
            continue;
    
        std::string address;
        bool is_anon = row.m_address.m_spend_public_key == crypto::null_pkey || row.m_address.m_view_public_key == crypto::null_pkey;
        if(!is_anon)
        {  
          if (row.m_has_payment_id)
            address = cryptonote::get_account_integrated_address_as_str(m_wallet->m_wallet->nettype(), row.m_address, row.m_payment_id);
          else if (row.m_has_view_skey)
            address = cryptonote::get_account_channel_address_as_str(m_wallet->m_wallet->nettype(), row.m_address.m_spend_public_key, row.m_view_skey);
          else
            address = get_account_address_as_str(m_wallet->m_wallet->nettype(), row.m_is_subaddress, row.m_address);
        }
        else
            address = epee::string_tools::pod_to_hex(row.m_address_hash);

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
