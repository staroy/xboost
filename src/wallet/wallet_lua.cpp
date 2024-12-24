#include "string_tools.h"
#include "hex.h"
//#include "misc_language.h"
#include "wallet_lua.h"
#include "packjson.h"
#include "lua-lldb.h"
#include "wallet_lua_json.h"
#include "zyre/zyre.hpp"
#include "zyre.h"

#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "wallet2.h"
#include "serialization/crypto.h"

#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <atomic>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.lua"

#include "cmsgpack.h"

namespace sol
{
  template <>
  struct lua_size<tools::lua::msgpack_out> : std::integral_constant<int, 1> {};
  template <>
  struct lua_type_of<tools::lua::msgpack_out> : std::integral_constant<sol::type, sol::type::poly> {};

  namespace stack
  {
    // return checker
    template <>
    struct unqualified_checker<tools::lua::msgpack_out, type::poly> {
      template <typename Handler>
      static bool check(lua_State* L, int index, Handler&& handler, record& tracking) {
        return true;
      }
    };

    // return getter
    template <>
    struct unqualified_getter<tools::lua::msgpack_out> {
      static tools::lua::msgpack_out get(lua_State* L, int index, record& tracking) {
        int top = lua_gettop(L);
        tools::lua::msgpack_out buf;
        if(top >= index)
          xpack(L, index, top, buf.data);
        return buf;
      }
    };

    // return pusher
    template <>
    struct unqualified_pusher<tools::lua::msgpack_out> {
      static int push(lua_State* L, const tools::lua::msgpack_out& buf) {
        if(!buf.data.empty())
          return xunpack(L, buf.data.data(), buf.data.size());
        lua_pushnil(L);
        return 1;
      }
    };

    // arguments pusher
    int push(lua_State *L, tools::lua::msgpack_in *m)
    {
      if(m->p && m->sz>0)
        return xunpack(L, m->p, m->sz);
      lua_pushnil(L);
      return 1;
    }
  }
}

extern std::atomic<bool> g_exit;

namespace tools {
  namespace lua {

    struct U64 { uint64_t v; };
    struct I64 { int64_t v; };
    struct tx_extra_data_t { std::vector<uint8_t> data; };

    class wallet2_interface
    {
      simple      *parent_;
      wallet2     *wallet_;
      std::mutex   wallet_mx_;
      bool         is_ref_;

    public:
      wallet2_interface(simple *parent, wallet2 *wallet);
      wallet2_interface(simple *parent);
      ~wallet2_interface();

      void generate(
        const crypto::secret_key& spendkey,
        const crypto::secret_key& viewkey,
        sol::this_state L);

      void open_or_create(
        const std::string name,
        const std::string pwd,
        const crypto::secret_key& spendkey,
        const crypto::secret_key& viewkey,
        sol::this_state L);

      void new_index(std::string k, sol::stack_object v);
      std::string cryptonote_name() { return wallet_->cryptonote_name(); }
      std::string coin_name() { return wallet_->coin_name(); }
      std::string millicoin_name() { return wallet_->millicoin_name(); }
      std::string microcoin_name() { return wallet_->microcoin_name(); }
      std::string nanocoin_name() { return wallet_->nanocoin_name(); }
      std::string picocoin_name() { return wallet_->picocoin_name(); }
      std::string get_wallet_name() { return boost::filesystem::path(wallet_->get_wallet_file()).filename().string(); }
      void set_attribute(const std::string& name, const std::string& value);
      sol::variadic_results get_attribute(const std::string& name, sol::this_state L);
      cryptonote::account_public_address get_address();
      sol::variadic_results get_address_book_row(int idx, sol::this_state L);
      int get_address_book_count();
      sol::variadic_results add_address_book_row(const tools::wallet2::address_book_row& row, sol::this_state L);
      bool set_address_book_row(int row_id, const tools::wallet2::address_book_row& row);
      sol::variadic_results get_address_book_row_id(const cryptonote::account_public_address &address, sol::this_state L);
      bool is_address_book_row_multi_user(int row_id);
      bool do_message_chat_send(const cryptonote::account_public_address& addr, const std::string& data, const std::string& description, const std::string& short_name, bool enable_comments, bool is_anon, const U64& amount, bool unprunable, int type, int freq);
      sol::variadic_results add_message_to_chat(const cryptonote::account_public_address& chat, const std::string& text, const std::string& description, const std::string& short_name, bool enable_comments, bool is_anon, const U64& amount, bool unprunable, sol::this_state L);
      sol::variadic_results get_message_from_chat(const cryptonote::account_public_address& chat, const U64& n, sol::this_state L);
      uint64_t get_message_chat_size(const cryptonote::account_public_address& chat);
      uint64_t get_message_chat_unread(const cryptonote::account_public_address& chat);
      uint64_t get_message_chat_timestamp(const cryptonote::account_public_address& chat);
      void commit_tx(tools::wallet2::pending_tx& ptx);
      sol::variadic_results get_transfers(sol::this_state L);
      sol::variadic_results create_transaction(const cryptonote::account_public_address &addr, bool is_subaddress, const U64& amount, int mixin_count, const U64& unlock_time, const tx_extra_data_t& tx_extra_data, std::string extra_nonce, int priority, int subaddr_account, std::vector<int> subaddr_indices_array, bool subtract_fee, sol::this_state L);
      std::string get_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message);
      sol::variadic_results check_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message, const std::string &sig_str, sol::this_state L);
      void set_refresh_from_block_height(const U64& height) { wallet_->set_refresh_from_block_height(height.v); }
      U64 get_refresh_from_block_height() { return {wallet_->get_refresh_from_block_height()}; }
      sol::variadic_results get_daemon_blockchain_height(sol::this_state L);
      sol::variadic_results refresh(sol::variadic_args args);
      U64 estimate_fee(
        bool use_per_byte_fee, bool use_rct, int n_inputs, int mixin, int n_outputs,
        int extra_size, bool bulletproof, bool clsag, bool bulletproof_plus, bool use_view_tags,
        const U64& base_fee, const U64& fee_quantization_mask)
      {
        return U64{
          wallet_->estimate_fee(use_per_byte_fee, use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag, bulletproof_plus, use_view_tags, base_fee.v, fee_quantization_mask.v)
        };
      }
      U64 get_base_fee(int priority) { return U64{ wallet_->get_base_fee(priority) }; }
      U64 get_fee_quantization_mask() { return U64{ wallet_->get_fee_quantization_mask() }; }
      U64 get_min_ring_size() { return U64{ wallet_->get_min_ring_size() }; }
      U64 get_max_ring_size() { return U64{ wallet_->get_max_ring_size() }; }
      U64 adjust_mixin(const U64& mixin) { return U64{ wallet_->adjust_mixin(mixin.v) }; }
      int adjust_priority(int priority) { return wallet_->adjust_priority(priority); }
      bool set_ring_database(const std::string &filename) { return wallet_->set_ring_database(filename); }
      std::string get_ring_database() { return wallet_->get_ring_database(); }
      U64 balance_all(bool strict) { return U64{ wallet_->balance_all(strict) }; }
      sol::variadic_results unlocked_balance_all(bool strict, sol::this_state L) {
        U64 blocks_to_unlock, time_to_unlock;
        U64 balance{ wallet_->unlocked_balance_all(strict, &blocks_to_unlock.v, &time_to_unlock.v) };
        sol::variadic_results rc;
        rc.push_back({ L, sol::in_place, balance });
        rc.push_back({ L, sol::in_place, blocks_to_unlock });
        rc.push_back({ L, sol::in_place, time_to_unlock });
        return rc;
      }
    };

    wallet2_interface::wallet2_interface(simple *parent, wallet2 *wallet)
      : parent_(parent), wallet_(wallet), is_ref_(true)
    {
    }

    wallet2_interface::wallet2_interface(simple *parent)
      : parent_(parent), wallet_(new wallet2(parent->wallet_->nettype())), is_ref_(false)
    {
    }

    void wallet2_interface::generate(
      const crypto::secret_key& spendkey,
      const crypto::secret_key& viewkey,
      sol::this_state L)
    {
      try
      {
        wallet_->enable_zyre(false);
        wallet_->enable_lua(false);
        
        cryptonote::account_public_address address;
        if (!crypto::secret_key_to_public_key(viewkey, address.m_view_public_key)) {
          auto e = epee::string_tools::pod_to_hex(viewkey);
          luaL_error(L,"failed to verify view key secret key: %s", e.c_str());
          return;
        }
        if (!crypto::secret_key_to_public_key(spendkey, address.m_spend_public_key)) {
          auto e = epee::string_tools::pod_to_hex(spendkey);
          luaL_error(L,"failed to verify spend key secret key: %s", e.c_str());
          return;
        }

        wallet_->generate("", "", address, spendkey, viewkey, false);

        wallet_->init(
          parent_->wallet_->get_daemon_address(),
          parent_->wallet_->get_daemon_login(),
          "", 0,
          parent_->wallet_->is_trusted_daemon()
        );
      }
      catch(const std::exception& e)
      {
        luaL_error(L,"Error wallet: %s", e.what());
      }
    }

    void wallet2_interface::open_or_create(
      const std::string name,
      const std::string pwd,
      const crypto::secret_key& spendkey,
      const crypto::secret_key& viewkey,
      sol::this_state L)
    {
      try
      {
        wallet_->enable_zyre(false);
        wallet_->enable_lua(false);
        
        std::string wallet_path = parent_->wallet_->get_wallet_file() + ".ast.shared";
        std::string wallet_name = wallet_path + "/" + name;
        
        if(!boost::filesystem::exists(wallet_name))
        {
          cryptonote::account_public_address address;
          if (!crypto::secret_key_to_public_key(viewkey, address.m_view_public_key)) {
            auto e = epee::string_tools::pod_to_hex(viewkey);
            luaL_error(L,"failed to verify view key secret key: %s", e.c_str());
            return;
          }
          if (!crypto::secret_key_to_public_key(spendkey, address.m_spend_public_key)) {
            auto e = epee::string_tools::pod_to_hex(spendkey);
            luaL_error(L,"failed to verify spend key secret key: %s", e.c_str());
            return;
          }

          boost::filesystem::create_directory(wallet_path);

          wallet_->generate(wallet_name, pwd, address, spendkey, viewkey, false);

          wallet_->init(
            parent_->wallet_->get_daemon_address(),
            parent_->wallet_->get_daemon_login(),
            "", 0,
            parent_->wallet_->is_trusted_daemon()
          );
        }
        else
        {
          wallet_->load(wallet_name, pwd);

          wallet_->init(
            parent_->wallet_->get_daemon_address(),
            parent_->wallet_->get_daemon_login(),
            "", 0,
            parent_->wallet_->is_trusted_daemon()
          );
        }
      }
      catch(const std::exception& e)
      {
        luaL_error(L,"Error wallet: %s", e.what());
      }
    }

    wallet2_interface::~wallet2_interface()
    {
      if(!is_ref_)
        delete wallet_;
    }

    void wallet2_interface::set_attribute(const std::string& name, const std::string& value)
    {
      wallet_->set_attribute(name, value);
    }

    sol::variadic_results wallet2_interface::get_attribute(const std::string& name, sol::this_state L)
    {
      sol::variadic_results rc;
      std::string value;
      if(wallet_->get_attribute(name, value))
        rc.push_back({ L, sol::in_place, value });
      else
        rc.push_back({ L, sol::in_place, sol::lua_nil });
      return rc;
    }

    cryptonote::account_public_address wallet2_interface::get_address() {
      return wallet_->get_address();
    }

    /*sol::variadic_results wallet2_interface::get_address_book(sol::this_state L)
    {
      std::lock_guard<std::mutex> lock(wallet_mx_);
      sol::variadic_results rc;
      rc.push_back({ L, sol::in_place, sol::as_table(wallet_->get_address_book()) });
      return rc;
    }*/
    sol::variadic_results wallet2_interface::get_address_book_row(int idx, sol::this_state L)
    {
      std::lock_guard<std::mutex> lock(wallet_mx_);
      sol::variadic_results rc;
      wallet2::address_book_row row;
      if(wallet_->get_address_book_row(idx, row))
      {
         rc.push_back({ L, sol::in_place, true });
         rc.push_back({ L, sol::in_place, row });
      }
      else
      {
         rc.push_back({ L, sol::in_place, false });
         rc.push_back({ L, sol::in_place, sol::lua_nil });
      }
      return rc;
    }
    int wallet2_interface::get_address_book_count()
    {
      std::lock_guard<std::mutex> lock(wallet_mx_);
      return int(wallet_->get_address_book_count());
    }
    sol::variadic_results wallet2_interface::add_address_book_row(const wallet2::address_book_row& row, sol::this_state L)
    {
      std::lock_guard<std::mutex> lock(wallet_mx_);
      size_t row_id;
      bool ok = wallet_->add_address_book_row(row, row_id);
      sol::variadic_results rc;
      rc.push_back({ L, sol::in_place_type<bool>, ok });
      rc.push_back({ L, sol::in_place_type<int>, int(row_id) });
      return rc;
    }
    bool wallet2_interface::set_address_book_row(int row_id, const wallet2::address_book_row& row)
    {
      std::lock_guard<std::mutex> lock(wallet_mx_);
      return wallet_->set_address_book_row(size_t(row_id), row);
    }
    sol::variadic_results wallet2_interface::get_address_book_row_id(const cryptonote::account_public_address &address, sol::this_state L)
    {
      std::lock_guard<std::mutex> lock(wallet_mx_); 
      size_t row_id = 0;
      bool ok = wallet_->get_address_book_row_id(address, row_id);
      sol::variadic_results rc;
      rc.push_back({ L, sol::in_place_type<bool>, ok });
      rc.push_back({ L, sol::in_place_type<int>, int(row_id) });
      return rc;
    }
    bool wallet2_interface::is_address_book_row_multi_user(int row_id)
    {
      std::lock_guard<std::mutex> lock(wallet_mx_);
      return wallet_->is_address_book_row_multi_user(size_t(row_id));
    }
    bool wallet2_interface::do_message_chat_send(const cryptonote::account_public_address& addr, const std::string& data, const std::string& description, const std::string& short_name, bool enable_comments, bool is_anon, const U64& amount, bool unprunable, int type, int freq)
    {
       std::lock_guard<std::mutex> lock(wallet_mx_);
       return wallet_->do_message_chat_send(addr, data, description, short_name, enable_comments, is_anon, amount.v, unprunable, type, freq);
    }
    sol::variadic_results wallet2_interface::add_message_to_chat(const cryptonote::account_public_address& chat, const std::string& text, const std::string& description, const std::string& short_name, bool enable_comments, bool is_anon, const U64& amount, bool unprunable, sol::this_state L)
    {
       std::lock_guard<std::mutex> lock(wallet_mx_);
       uint64_t n;
       bool ok = wallet_->add_message_to_chat(chat, text, description, short_name, enable_comments, is_anon, amount.v, unprunable, n);
       sol::variadic_results rc;
       rc.push_back({ L, sol::in_place_type<bool>, ok });
       rc.push_back({ L, sol::in_place_type<U64>, U64{n} });
       return rc;
    }
    sol::variadic_results wallet2_interface::get_message_from_chat(const cryptonote::account_public_address& chat, const U64& n, sol::this_state L)
    {
       std::lock_guard<std::mutex> lock(wallet_mx_);
       wallet2::message_list_row row;
       bool ok = wallet_->get_message_from_chat(chat, n.v, row);
       sol::variadic_results rc;
       rc.push_back({ L, sol::in_place_type<bool>, ok });
       rc.push_back({ L, sol::in_place_type<wallet2::message_list_row>, row });
       return rc;
    }
    uint64_t wallet2_interface::get_message_chat_size(const cryptonote::account_public_address& chat)
    {
      std::lock_guard<std::mutex> lock(wallet_mx_);
      return wallet_->get_message_chat_size(chat);
    }
    uint64_t wallet2_interface::get_message_chat_unread(const cryptonote::account_public_address& chat)
    {
      std::lock_guard<std::mutex> lock(wallet_mx_);
      return wallet_->get_message_chat_unread(chat);
    }
    uint64_t wallet2_interface::get_message_chat_timestamp(const cryptonote::account_public_address& chat)
    {
      std::lock_guard<std::mutex> lock(wallet_mx_);
      return wallet_->get_message_chat_timestamp(chat);
    }
    void wallet2_interface::new_index(std::string k, sol::stack_object v)
    {
      if(!is_ref_)
        return;
      if(v.get_type() == sol::type::function)
      {
        parent_->meth_[k] = v.as<sol::protected_function>();
      }
      else if(v.get_type() == sol::type::boolean)
      {
        if(!v.as<bool>())
        {
          auto it = parent_->meth_.find(k);
          if(it != parent_->meth_.end())
            parent_->meth_.erase(it);
        }
      }
      else if(v.is<sol::lua_nil_t>())
      {
        auto it = parent_->meth_.find(k);
        if(it != parent_->meth_.end())
          parent_->meth_.erase(it);
      }
    }
    void wallet2_interface::commit_tx(tools::wallet2::pending_tx& ptx)
    {
      wallet_->commit_tx(ptx);
    }
    sol::variadic_results wallet2_interface::get_transfers(sol::this_state L)
    {
      std::vector<tools::wallet2::transfer_details> transfers;
      wallet_->get_transfers(transfers);
      sol::variadic_results rc;
      rc.push_back({ L, sol::in_place, sol::as_table(transfers) });
      return rc;
    }
    sol::variadic_results wallet2_interface::create_transaction(
      const cryptonote::account_public_address &addr,
      bool is_subaddress,
      const U64& amount,
      int mixin_count,
      const U64& unlock_time,
      const tx_extra_data_t& tx_extra_data,
      std::string extra_nonce,
      int priority,
      int subaddr_account,
      std::vector<int> subaddr_indices_array,
      bool subtract_fee,
      sol::this_state L)
    {
      bool ok = true;
      std::vector<tools::wallet2::pending_tx> ptx;
      std::vector<crypto::public_key> signers;
      std::string error_str;
      uint32_t adjusted_priority = wallet_->adjust_priority(static_cast<uint32_t>(priority));
      std::set<uint32_t> subaddr_indices;
      for(auto it=subaddr_indices_array.begin(); it<subaddr_indices_array.end(); it++)
        subaddr_indices.insert(*it);
      do {
        std::vector<uint8_t> extra = tx_extra_data.data;
        std::string extra_nonce;

        std::vector<cryptonote::tx_destination_entry> dsts;
        if (amount.v > 0) {
          cryptonote::tx_destination_entry de;
          de.original = cryptonote::get_account_address_as_str(wallet_->nettype(), is_subaddress, addr);
          de.addr = addr;
          de.amount = amount.v;
          de.is_subaddress = is_subaddress;
          de.is_integrated = false;
          dsts.push_back(de);
        }
        else
        {
          error_str = tr("failed to set amount is not zero");
          ok = false;
          break;
        }

        if (!extra_nonce.empty() && !cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
          error_str = tr("failed to set up payment id, though it was decoded correctly");
          ok = false;
          break;
        }
  
        std::vector<std::string> tx_device_aux;
        std::vector<crypto::key_image> key_images;

        try {
          mixin_count = std::min<int>(std::max(mixin_count, 1), wallet_->get_max_ring_size());
          size_t fake_outs_count = mixin_count - 1;

          tools::wallet2::unique_index_container subtract_fee_from_outputs;
          if(subtract_fee) subtract_fee_from_outputs.insert(0);

          ptx = wallet_->create_transactions_2(dsts, fake_outs_count, unlock_time.v,
                       adjusted_priority, extra, subaddr_account, subaddr_indices, subtract_fee_from_outputs);

          // If the device being used is HW device with cold signing protocol, cold sign then.
          if (wallet_->get_account().get_device().has_tx_cold_sign())
          {
            tools::wallet2::signed_tx_set exported_txs;
            std::vector<cryptonote::address_parse_info> dsts_info;

            wallet_->cold_sign_tx(ptx, exported_txs, dsts_info, tx_device_aux);
            key_images = exported_txs.key_images;
            ptx = exported_txs.ptx;
          }

          if (wallet_->multisig())
          {
            auto tx_set = wallet_->make_multisig_tx_set(ptx);
            ptx = tx_set.m_ptx;
            for(auto it=tx_set.m_signers.begin(); it!=tx_set.m_signers.end(); it++)
              signers.push_back(*it);
          }
        } catch (const tools::error::daemon_busy&) {
          // TODO: make it translatable with "tr"?
          error_str = tr("daemon is busy. Please try again later.");
          ok = false;
        } catch (const tools::error::no_connection_to_daemon&) {
          error_str = tr("no connection to daemon. Please make sure daemon is running.");
          ok = false;
        } catch (const tools::error::wallet_rpc_error& e) {
          error_str = tr("RPC error: ") +  e.to_string();
          ok = false;
        } catch (const tools::error::get_outs_error &e) {
          error_str = (boost::format(tr("failed to get outputs to mix: %s")) % e.what()).str();
          ok = false;
        } catch (const tools::error::not_enough_unlocked_money& e) {
          std::ostringstream writer;
          writer << boost::format(tr("not enough money to transfer, available only %s, sent amount %s")) %
                    cryptonote::print_money(e.available()) %
                    cryptonote::print_money(e.tx_amount());
          error_str = writer.str();
          ok = false;
        } catch (const tools::error::not_enough_money& e) {
          std::ostringstream writer;
          writer << boost::format(tr("not enough money to transfer, overall balance only %s, sent amount %s")) %
                    cryptonote::print_money(e.available()) %
                    cryptonote::print_money(e.tx_amount());
          error_str = writer.str();
          ok = false;
        } catch (const tools::error::tx_not_possible& e) {
          std::ostringstream writer;
          writer << boost::format(tr("not enough money to transfer, available only %s, transaction amount %s = %s + %s (fee)")) %
                    cryptonote::print_money(e.available()) %
                    cryptonote::print_money(e.tx_amount() + e.fee())  %
                    cryptonote::print_money(e.tx_amount()) %
                    cryptonote::print_money(e.fee());
          error_str = writer.str();
          ok = false;
        } catch (const tools::error::not_enough_outs_to_mix& e) {
          std::ostringstream writer;
          writer << tr("not enough outputs for specified ring size") << " = " << (e.mixin_count() + 1) << ":";
          for (const std::pair<uint64_t, uint64_t> outs_for_amount : e.scanty_outs()) {
            writer << "\n" << tr("output amount") << " = " << cryptonote::print_money(outs_for_amount.first) << ", " << tr("found outputs to use") << " = " << outs_for_amount.second;
          }
          writer << "\n" << tr("Please sweep unmixable outputs.");
          error_str = writer.str();
          ok = false;
        } catch (const tools::error::tx_not_constructed&) {
          error_str = tr("transaction was not constructed");
          ok = false;
        } catch (const tools::error::tx_rejected& e) {
          std::ostringstream writer;
          writer << (boost::format(tr("transaction %s was rejected by daemon with status: ")) % get_transaction_hash(e.tx())) <<  e.status();
          error_str = writer.str();
          ok = false;
        } catch (const tools::error::tx_sum_overflow& e) {
          error_str = e.what();
          ok = false;
        } catch (const tools::error::zero_amount&) {
          error_str = tr("destination amount is zero");
          ok = false;
        } catch (const tools::error::zero_destination&) {
          error_str = tr("transaction has no destination");
          ok = false;
        } catch (const tools::error::tx_too_big& e) {
          error_str = tr("failed to find a suitable way to split transactions");
          ok = false;
        } catch (const tools::error::transfer_error& e) {
          error_str = std::string(tr("unknown transfer error: ")) + e.what();
          ok = false;
        } catch (const tools::error::wallet_internal_error& e) {
          error_str = std::string(tr("internal error: ")) + e.what();
          ok = false;
        } catch (const std::exception& e) {
          error_str = std::string(tr("unexpected error: ")) + e.what();
          ok = false;
        } catch (...) {
          error_str = tr("unknown error");
          ok = false;
        }
      } while (false);

      sol::variadic_results rc;
      rc.push_back({ L, sol::in_place_type<bool>, ok });
      rc.push_back({ L, sol::in_place, sol::as_table(ptx) });
      rc.push_back({ L, sol::in_place, sol::as_table(signers) });
      rc.push_back({ L, sol::in_place_type<std::string>, error_str });
      return rc;
    }
    std::string wallet2_interface::get_tx_proof(
        const crypto::hash &txid,
        const cryptonote::account_public_address &address,
        bool is_subaddress, const std::string &message)
    {
      return wallet_->get_tx_proof(txid, address, is_subaddress, message);
    }
    sol::variadic_results wallet2_interface::check_tx_proof(
        const crypto::hash &txid,
        const cryptonote::account_public_address &address,
        bool is_subaddress,
        const std::string &message,
        const std::string &sig_str,
        sol::this_state L)
    {
      uint64_t received; bool in_pool; uint64_t confirmations;
      bool ok = wallet_->check_tx_proof(txid, address, is_subaddress, message, sig_str, received, in_pool, confirmations);
      sol::variadic_results rc;
      rc.push_back({ L, sol::in_place_type<bool>, ok });
      rc.push_back({ L, sol::in_place_type<U64>, U64{received} });
      rc.push_back({ L, sol::in_place_type<bool>, in_pool });
      rc.push_back({ L, sol::in_place_type<U64>, U64{confirmations} });
      return rc;
    }
    sol::variadic_results wallet2_interface::get_daemon_blockchain_height(sol::this_state L)
    {
      std::string err;
      uint64_t height = wallet_->get_daemon_blockchain_height(err);
      sol::variadic_results rc;
      rc.push_back({ L, sol::in_place_type<bool>, err.empty() });
      rc.push_back({ L, sol::in_place_type<U64>, U64{height} });
      rc.push_back({ L, sol::in_place, err });
      return rc;
    }
    sol::variadic_results wallet2_interface::refresh(sol::variadic_args args)
    {
      bool trusted_daemon = false;
      uint64_t start_height = wallet_->get_refresh_from_block_height();
      bool check_pool = true;
      bool try_incremental = true;
      uint64_t max_blocks = std::numeric_limits<uint64_t>::max();

      uint64_t blocks_fetched = 0;
      bool received_money = false;

      lua_State *L = args.lua_state();
      int top = args.top();
      int first=args.stack_index();
      for(int n=first; n<=top; n++)
      {
        auto a = sol::stack_object(L, n);
        auto t = a.get_type();
        switch(n - first)
        {
        case 0: if(t == sol::type::boolean) trusted_daemon = a.as<bool>(); break;
        case 1:
          if(t == sol::type::userdata) start_height = a.as<uint64_t>(); else
          if(a.is<double>()) start_height = uint64_t(a.as<double>()); else
          if(a.is<int>()) start_height = uint64_t(a.as<int>());
          break;
        case 2: if(t == sol::type::boolean) check_pool = a.as<bool>(); break;
        case 3: if(t == sol::type::boolean) try_incremental = a.as<bool>(); break;
        case 4:
          if(t == sol::type::userdata) max_blocks = a.as<uint64_t>(); else
          if(a.is<double>()) max_blocks = uint64_t(a.as<double>()); else
          if(a.is<int>()) max_blocks = uint64_t(a.as<int>());
          break;
        }
      }

      wallet_->refresh(trusted_daemon, start_height, blocks_fetched, received_money, check_pool, try_incremental, max_blocks);

      sol::variadic_results rc;
      rc.push_back({ L, sol::in_place_type<bool>, received_money || blocks_fetched > 0 });
      rc.push_back({ L, sol::in_place_type<U64>, U64{blocks_fetched} });
      rc.push_back({ L, sol::in_place_type<bool>, received_money });
      return rc;
    }

  simple::simple(wallet2 *wallet)
    : wallet_(wallet)
    , interface_(std::make_shared<wallet2_interface>(this, wallet))
    , root_path_(boost::filesystem::path(wallet->get_wallet_file()).parent_path().string())
  {
    if(wallet->is_use_zyre())
      zyre::init();
  }

  simple::~simple()
  {
    clear();
  }

  void simple::clear()
  {
    for(auto it = meth_.begin(); it != meth_.end(); it++)
      it->second = sol::lua_nil;

    zyre::destroy();
  }

  void insert_money_decimal_point(std::string &s, int decimal_point)
  {
    if (decimal_point == -1)
      decimal_point = 12;
    if(s.size() < size_t(decimal_point)+1)
    {
      s.insert(0, decimal_point+1 - s.size(), '0');
    }
    if (decimal_point > 0)
      s.insert(s.size() - decimal_point, ".");
  }

  struct CFG
  {
    U64 c_CRYPTONOTE_DNS_TIMEOUT_MS                            ;
    U64 c_CRYPTONOTE_MAX_BLOCK_NUMBER                          ;
    U64 c_CRYPTONOTE_MAX_TX_SIZE                               ;
    U64 c_CRYPTONOTE_MAX_TX_PER_BLOCK                          ;
    U64 c_CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER               ;
    U64 c_CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW                 ;
    int c_CURRENT_TRANSACTION_VERSION                          ;
    int c_CURRENT_BLOCK_MAJOR_VERSION                          ;
    int c_CURRENT_BLOCK_MINOR_VERSION                          ;
    U64 c_CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT                   ;
    U64 c_CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE                  ;
    U64 c_BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW                    ;
    U64 c_MONEY_SUPPLY                                         ;
    U64 c_EMISSION_SPEED_FACTOR_PER_MINUTE                     ;
    U64 c_FINAL_SUBSIDY_PER_MINUTE                             ;
    U64 c_CRYPTONOTE_REWARD_BLOCKS_WINDOW                      ;
    U64 c_CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2         ;
    U64 c_CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1         ;
    U64 c_CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5         ;
    U64 c_CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE        ;
    U64 c_CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR      ;
    U64 c_CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE               ;
    int c_CRYPTONOTE_DISPLAY_DECIMAL_POINT                     ;
    U64 c_COIN                                                 ;
    U64 c_FEE_PER_KB_OLD                                        ;
    U64 c_FEE_PER_KB                                            ;
    U64 c_FEE_PER_BYTE                                          ;
    U64 c_DYNAMIC_FEE_PER_KB_BASE_FEE                           ;
    U64 c_DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD                  ;
    U64 c_DYNAMIC_FEE_PER_KB_BASE_FEE_V5                        ;
    U64 c_DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT              ;
    U64 c_ORPHANED_BLOCKS_MAX_COUNT                             ;
    U64 c_DIFFICULTY_TARGET_V2                                  ;
    U64 c_DIFFICULTY_TARGET_V1                                  ;
    U64 c_DIFFICULTY_WINDOW                                     ;
    U64 c_DIFFICULTY_LAG                                        ;
    U64 c_DIFFICULTY_CUT                                        ;
    U64 c_DIFFICULTY_BLOCKS_COUNT                               ;
    U64 c_CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1         ;
    U64 c_CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2         ;
    U64 c_CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS             ;
    U64 c_DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN                   ;
    U64 c_BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT                ;
    U64 c_BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT                    ;
    U64 c_BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4             ;
    U64 c_BLOCKS_SYNCHRONIZING_DEFAULT_COUNT                    ;
    U64 c_BLOCKS_SYNCHRONIZING_MAX_COUNT                        ;
    U64 c_CRYPTONOTE_MEMPOOL_TX_LIVETIME                        ;
    U64 c_CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME         ;
    int c_CRYPTONOTE_DANDELIONPP_STEMS                          ;
    int c_CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY              ;
    int c_CRYPTONOTE_DANDELIONPP_MIN_EPOCH                      ;
    int c_CRYPTONOTE_DANDELIONPP_EPOCH_RANGE                    ;
    int c_CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE                  ;
    int c_CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE                ;
    int c_CRYPTONOTE_NOISE_MIN_EPOCH                            ;
    int c_CRYPTONOTE_NOISE_EPOCH_RANGE                          ;
    int c_CRYPTONOTE_NOISE_MIN_DELAY                            ;
    int c_CRYPTONOTE_NOISE_DELAY_RANGE                          ;
    int c_CRYPTONOTE_NOISE_BYTES                                ;
    int c_CRYPTONOTE_NOISE_CHANNELS                             ;
    U64 c_CRYPTONOTE_FORWARD_DELAY_BASE                         ;
    U64 c_CRYPTONOTE_FORWARD_DELAY_AVERAGE                      ;
    U64 c_CRYPTONOTE_MAX_FRAGMENTS                              ;
    U64 c_COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT           ;
    U64 c_COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT              ;
    U64 c_MAX_RPC_CONTENT_LENGTH                                ;
    std::string c_CRYPTONOTE_NAME                               ;
    std::string c_COIN_NAME                                     ;
    std::string c_MILLICOIN_NAME                                ;
    std::string c_MICROCOIN_NAME                                ;
    std::string c_NANOCOIN_NAME                                 ;
    std::string c_PICOCOIN_NAME                                 ;
    U64 c_CRYPTONOTE_PRUNING_STRIPE_SIZE                        ;
    U64 c_CRYPTONOTE_PRUNING_LOG_STRIPES                        ;
    U64 c_CRYPTONOTE_PRUNING_TIP_BLOCKS                         ;
    U64 c_MAX_TX_EXTRA_SIZE                                     ;
    U64 c_MAX_TX_EXTRA_MSG_SIZE                                 ;
    U64 c_MAX_TX_MSG_PRUNABLE_SIZE                              ;
    U64 c_MSG_TX_AMOUNT                                         ;
    U64 c_MSG_TX_EXTRA_TYPE                                     ;
    U64 c_MSG_TX_EXTRA_CTRL                                     ;
    U64 c_MSG_TX_EXTRA_USER                                     ;
    U64 c_MSG_TX_EXTRA_FREQ_0                                   ;
    U64 c_ATOMIC_SWAP_MSG_TX_EXTRA_TYPE                         ;
    U64 c_ATOMIC_SWAP_HASH_X_UNLOCK_TIME                        ;
    U64 c_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX               ;
    U64 c_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX    ;
    U64 c_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX       ;
    U64 c_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX            ;
    int c_P2P_DEFAULT_PORT                                      ;
    int c_RPC_DEFAULT_PORT                                      ;
    int c_ZMQ_RPC_DEFAULT_PORT                                  ;
    std::string c_NETWORK_ID                                    ;
    std::string c_GENESIS_TX                                    ;
    U64 c_GENESIS_NONCE                                         ;
    U64 c_GENESIS_TIMESTAMP                                     ;

    U64 c_t_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX             ;
    U64 c_t_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX  ;
    U64 c_t_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX     ;
    U64 c_t_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX          ;
    int c_t_P2P_DEFAULT_PORT                                    ;
    int c_t_RPC_DEFAULT_PORT                                    ;
    int c_t_ZMQ_RPC_DEFAULT_PORT                                ;
    std::string c_t_NETWORK_ID                                  ;
    std::string c_t_GENESIS_TX                                  ;
    U64 c_t_GENESIS_NONCE                                       ;
    U64 c_t_GENESIS_TIMESTAMP                                   ;

    U64 c_s_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX             ;
    U64 c_s_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX  ;
    U64 c_s_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX     ;
    U64 c_s_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX          ;
    int c_s_P2P_DEFAULT_PORT                                    ;
    int c_s_RPC_DEFAULT_PORT                                    ;
    int c_s_ZMQ_RPC_DEFAULT_PORT                                ;
    std::string c_s_NETWORK_ID                                  ;
    std::string c_s_GENESIS_TX                                  ;
    U64 c_s_GENESIS_NONCE                                       ;
    U64 c_s_GENESIS_TIMESTAMP                                   ;

    void init()
    {
      c_CRYPTONOTE_DNS_TIMEOUT_MS                             =  U64 {CRYPTONOTE_DNS_TIMEOUT_MS};
      c_CRYPTONOTE_MAX_BLOCK_NUMBER                           =  U64 {CRYPTONOTE_MAX_BLOCK_NUMBER};
      c_CRYPTONOTE_MAX_TX_SIZE                                =  U64 {CRYPTONOTE_MAX_TX_SIZE};
      c_CRYPTONOTE_MAX_TX_PER_BLOCK                           =  U64 {CRYPTONOTE_MAX_TX_PER_BLOCK};
      c_CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER                =  U64 {CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER};
      c_CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW                  =  U64 {CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW};
      c_CURRENT_TRANSACTION_VERSION                           =  int (CURRENT_TRANSACTION_VERSION);
      c_CURRENT_BLOCK_MAJOR_VERSION                           =  int (CURRENT_BLOCK_MAJOR_VERSION);
      c_CURRENT_BLOCK_MINOR_VERSION                           =  int (CURRENT_BLOCK_MINOR_VERSION);
      c_CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT                    =  U64 {CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT};
      c_CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE                   =  U64 {CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE};
      c_BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW                     =  U64 {BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW};
      c_MONEY_SUPPLY                                          =  U64 {MONEY_SUPPLY};
      c_EMISSION_SPEED_FACTOR_PER_MINUTE                      =  U64 {EMISSION_SPEED_FACTOR_PER_MINUTE};
      c_FINAL_SUBSIDY_PER_MINUTE                              =  U64 {FINAL_SUBSIDY_PER_MINUTE};
      c_CRYPTONOTE_REWARD_BLOCKS_WINDOW                       =  U64 {CRYPTONOTE_REWARD_BLOCKS_WINDOW};
      c_CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2          =  U64 {CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2};
      c_CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1          =  U64 {CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1};
      c_CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5          =  U64 {CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5};
      c_CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE         =  U64 {CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE};
      c_CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR       =  U64 {CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR};
      c_CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE                =  U64 {CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE};
      c_CRYPTONOTE_DISPLAY_DECIMAL_POINT                      =  int  (CRYPTONOTE_DISPLAY_DECIMAL_POINT);
      c_COIN                                                  =  U64 {COIN};
      c_FEE_PER_KB_OLD                                        =  U64 {FEE_PER_KB_OLD};
      c_FEE_PER_KB                                            =  U64 {FEE_PER_KB};
      c_FEE_PER_BYTE                                          =  U64 {FEE_PER_BYTE};
      c_DYNAMIC_FEE_PER_KB_BASE_FEE                           =  U64 {DYNAMIC_FEE_PER_KB_BASE_FEE};
      c_DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD                  =  U64 {DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD};
      c_DYNAMIC_FEE_PER_KB_BASE_FEE_V5                        =  U64 {DYNAMIC_FEE_PER_KB_BASE_FEE_V5};
      c_DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT              =  U64 {DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT};
      c_ORPHANED_BLOCKS_MAX_COUNT                             =  U64 {ORPHANED_BLOCKS_MAX_COUNT};
      c_DIFFICULTY_TARGET_V2                                  =  U64 {DIFFICULTY_TARGET_V2};
      c_DIFFICULTY_TARGET_V1                                  =  U64 {DIFFICULTY_TARGET_V1};
      c_DIFFICULTY_WINDOW                                     =  U64 {DIFFICULTY_WINDOW};
      c_DIFFICULTY_LAG                                        =  U64 {DIFFICULTY_LAG};
      c_DIFFICULTY_CUT                                        =  U64 {DIFFICULTY_CUT};
      c_DIFFICULTY_BLOCKS_COUNT                               =  U64 {DIFFICULTY_BLOCKS_COUNT};
      c_CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1         =  U64 {CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1};
      c_CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2         =  U64 {CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2};
      c_CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS             =  U64 {CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS};
      c_DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN                   =  U64 {DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN};
      c_BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT                =  U64 {BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT};
      c_BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT                    =  U64 {BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT};
      c_BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4             =  U64 {BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4};
      c_BLOCKS_SYNCHRONIZING_DEFAULT_COUNT                    =  U64 {BLOCKS_SYNCHRONIZING_DEFAULT_COUNT};
      c_BLOCKS_SYNCHRONIZING_MAX_COUNT                        =  U64 {BLOCKS_SYNCHRONIZING_MAX_COUNT};
      c_CRYPTONOTE_MEMPOOL_TX_LIVETIME                        =  U64 {CRYPTONOTE_MEMPOOL_TX_LIVETIME};
      c_CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME         =  U64 {CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME};
      c_CRYPTONOTE_DANDELIONPP_STEMS                          =  int (CRYPTONOTE_DANDELIONPP_STEMS);
      c_CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY              =  int (CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY);
      c_CRYPTONOTE_DANDELIONPP_MIN_EPOCH                      =  int (CRYPTONOTE_DANDELIONPP_MIN_EPOCH);
      c_CRYPTONOTE_DANDELIONPP_EPOCH_RANGE                    =  int (CRYPTONOTE_DANDELIONPP_EPOCH_RANGE);
      c_CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE                  =  int (CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE);
      c_CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE                =  int (CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE);
      c_CRYPTONOTE_NOISE_MIN_EPOCH                            =  int (CRYPTONOTE_NOISE_MIN_EPOCH);
      c_CRYPTONOTE_NOISE_EPOCH_RANGE                          =  int (CRYPTONOTE_NOISE_EPOCH_RANGE);
      c_CRYPTONOTE_NOISE_MIN_DELAY                            =  int (CRYPTONOTE_NOISE_MIN_DELAY);
      c_CRYPTONOTE_NOISE_DELAY_RANGE                          =  int (CRYPTONOTE_NOISE_DELAY_RANGE);
      c_CRYPTONOTE_NOISE_BYTES                                =  int (CRYPTONOTE_NOISE_BYTES);
      c_CRYPTONOTE_NOISE_CHANNELS                             =  int (CRYPTONOTE_NOISE_CHANNELS);
      c_CRYPTONOTE_FORWARD_DELAY_BASE                         =  U64 {CRYPTONOTE_FORWARD_DELAY_BASE};
      c_CRYPTONOTE_FORWARD_DELAY_AVERAGE                      =  U64 {CRYPTONOTE_FORWARD_DELAY_AVERAGE};
      c_CRYPTONOTE_MAX_FRAGMENTS                              =  U64 {CRYPTONOTE_MAX_FRAGMENTS};
      c_COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT           =  U64 {COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT};
      c_COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT              =  U64 {COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT};
      c_MAX_RPC_CONTENT_LENGTH                                =  U64 {MAX_RPC_CONTENT_LENGTH};
      c_CRYPTONOTE_NAME                                       =  CRYPTONOTE_NAME;
      c_COIN_NAME                                             =  COIN_NAME;      
      c_MILLICOIN_NAME                                        =  MILLICOIN_NAME; 
      c_MICROCOIN_NAME                                        =  MICROCOIN_NAME; 
      c_NANOCOIN_NAME                                         =  NANOCOIN_NAME;  
      c_PICOCOIN_NAME                                         =  PICOCOIN_NAME;  
      c_CRYPTONOTE_PRUNING_STRIPE_SIZE                        =  U64 {CRYPTONOTE_PRUNING_STRIPE_SIZE};
      c_CRYPTONOTE_PRUNING_LOG_STRIPES                        =  U64 {CRYPTONOTE_PRUNING_LOG_STRIPES};
      c_CRYPTONOTE_PRUNING_TIP_BLOCKS                         =  U64 {CRYPTONOTE_PRUNING_TIP_BLOCKS};
      c_MAX_TX_EXTRA_SIZE                                     =  U64 {MAX_TX_EXTRA_SIZE};
      c_MAX_TX_EXTRA_MSG_SIZE                                 =  U64 {MAX_TX_EXTRA_MSG_SIZE};
      c_MAX_TX_MSG_PRUNABLE_SIZE                              =  U64 {MAX_TX_MSG_PRUNABLE_SIZE};
      c_MSG_TX_AMOUNT                                         =  U64 {MSG_TX_AMOUNT};
      c_MSG_TX_EXTRA_TYPE                                     =  U64 {MSG_TX_EXTRA_TYPE};
      c_MSG_TX_EXTRA_CTRL                                     =  U64 {MSG_TX_EXTRA_CTRL};
      c_MSG_TX_EXTRA_USER                                     =  U64 {MSG_TX_EXTRA_USER};
      c_MSG_TX_EXTRA_FREQ_0                                   =  U64 {MSG_TX_EXTRA_FREQ_0};
      c_ATOMIC_SWAP_MSG_TX_EXTRA_TYPE                         =  U64 {ATOMIC_SWAP_MSG_TX_EXTRA_TYPE};
      c_ATOMIC_SWAP_HASH_X_UNLOCK_TIME                        =  U64 {ATOMIC_SWAP_HASH_X_UNLOCK_TIME};
      c_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX               =  U64 {config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX};
      c_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX    =  U64 {config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX};
      c_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX       =  U64 {config::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX};
      c_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX            =  U64 {config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX};
      c_P2P_DEFAULT_PORT                                      =  int (config::P2P_DEFAULT_PORT);
      c_RPC_DEFAULT_PORT                                      =  int (config::RPC_DEFAULT_PORT);
      c_ZMQ_RPC_DEFAULT_PORT                                  =  int (config::ZMQ_RPC_DEFAULT_PORT);
      c_NETWORK_ID                                            =  boost::lexical_cast<std::string>(config::NETWORK_ID);
      c_GENESIS_TX                                            =  config::GENESIS_TX;
      c_GENESIS_NONCE                                         =  U64 {config::GENESIS_NONCE};
      c_GENESIS_TIMESTAMP                                     =  U64 {config::GENESIS_TIMESTAMP};

      c_t_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX             =  U64 {config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX};
      c_t_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX  =  U64 {config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX};
      c_t_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX     =  U64 {config::testnet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX};
      c_t_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX          =  U64 {config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX};
      c_t_P2P_DEFAULT_PORT                                    =  int (config::testnet::P2P_DEFAULT_PORT);
      c_t_RPC_DEFAULT_PORT                                    =  int (config::testnet::RPC_DEFAULT_PORT);
      c_t_ZMQ_RPC_DEFAULT_PORT                                =  int (config::testnet::ZMQ_RPC_DEFAULT_PORT);
      c_t_NETWORK_ID                                          =  boost::lexical_cast<std::string>(config::testnet::NETWORK_ID);
      c_t_GENESIS_TX                                          =  config::testnet::GENESIS_TX;
      c_t_GENESIS_NONCE                                       =  U64 {config::testnet::GENESIS_NONCE};
      c_t_GENESIS_TIMESTAMP                                   =  U64 {config::testnet::GENESIS_TIMESTAMP};

      c_s_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX             =  U64 {config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX};
      c_s_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX  =  U64 {config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX};
      c_s_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX     =  U64 {config::stagenet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX};
      c_s_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX          =  U64 {config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX};
      c_s_P2P_DEFAULT_PORT                                    =  int (config::stagenet::P2P_DEFAULT_PORT);
      c_s_RPC_DEFAULT_PORT                                    =  int (config::stagenet::RPC_DEFAULT_PORT);
      c_s_ZMQ_RPC_DEFAULT_PORT                                =  int (config::stagenet::ZMQ_RPC_DEFAULT_PORT);
      c_s_NETWORK_ID                                          =  boost::lexical_cast<std::string>(config::stagenet::NETWORK_ID);
      c_s_GENESIS_TX                                          =  config::stagenet::GENESIS_TX;
      c_s_GENESIS_NONCE                                       =  U64 {config::stagenet::GENESIS_NONCE};
      c_s_GENESIS_TIMESTAMP                                   =  U64 {config::stagenet::GENESIS_TIMESTAMP};
    }
  };

  CFG cfg;

  void reg_config(sol::table& cryptonote)
  {
    cfg.init();

    auto cfg_ut = cryptonote.new_usertype<CFG>("cryptonote_config");

    cfg_ut.set("CRYPTONOTE_DNS_TIMEOUT_MS",                             sol::readonly(&CFG::c_CRYPTONOTE_DNS_TIMEOUT_MS));
    cfg_ut.set("CRYPTONOTE_MAX_BLOCK_NUMBER",                           sol::readonly(&CFG::c_CRYPTONOTE_MAX_BLOCK_NUMBER));
    cfg_ut.set("CRYPTONOTE_MAX_TX_SIZE",                                sol::readonly(&CFG::c_CRYPTONOTE_MAX_TX_SIZE));
    cfg_ut.set("CRYPTONOTE_MAX_TX_PER_BLOCK",                           sol::readonly(&CFG::c_CRYPTONOTE_MAX_TX_PER_BLOCK));
    cfg_ut.set("CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER",                sol::readonly(&CFG::c_CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER));
    cfg_ut.set("CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW",                  sol::readonly(&CFG::c_CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW));
    cfg_ut.set("CURRENT_TRANSACTION_VERSION",                           sol::readonly(&CFG::c_CURRENT_TRANSACTION_VERSION));
    cfg_ut.set("CURRENT_BLOCK_MAJOR_VERSION",                           sol::readonly(&CFG::c_CURRENT_BLOCK_MAJOR_VERSION));
    cfg_ut.set("CURRENT_BLOCK_MINOR_VERSION",                           sol::readonly(&CFG::c_CURRENT_BLOCK_MINOR_VERSION));
    cfg_ut.set("CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT",                    sol::readonly(&CFG::c_CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT));
    cfg_ut.set("CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE",                   sol::readonly(&CFG::c_CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE));
    cfg_ut.set("BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW",                     sol::readonly(&CFG::c_BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW));
    cfg_ut.set("MONEY_SUPPLY",                                          sol::readonly(&CFG::c_MONEY_SUPPLY));
    cfg_ut.set("EMISSION_SPEED_FACTOR_PER_MINUTE",                      sol::readonly(&CFG::c_EMISSION_SPEED_FACTOR_PER_MINUTE));
    cfg_ut.set("FINAL_SUBSIDY_PER_MINUTE",                              sol::readonly(&CFG::c_FINAL_SUBSIDY_PER_MINUTE));
    cfg_ut.set("CRYPTONOTE_REWARD_BLOCKS_WINDOW",                       sol::readonly(&CFG::c_CRYPTONOTE_REWARD_BLOCKS_WINDOW));
    cfg_ut.set("CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2",          sol::readonly(&CFG::c_CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2));
    cfg_ut.set("CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1",          sol::readonly(&CFG::c_CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1));
    cfg_ut.set("CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5",          sol::readonly(&CFG::c_CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5));
    cfg_ut.set("CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE",         sol::readonly(&CFG::c_CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE));
    cfg_ut.set("CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR",       sol::readonly(&CFG::c_CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR));
    cfg_ut.set("CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE",                sol::readonly(&CFG::c_CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE));
    cfg_ut.set("CRYPTONOTE_DISPLAY_DECIMAL_POINT",                      sol::readonly(&CFG::c_CRYPTONOTE_DISPLAY_DECIMAL_POINT));
    cfg_ut.set("COIN",                                                  sol::readonly(&CFG::c_COIN));
    cfg_ut.set("FEE_PER_KB_OLD",                                        sol::readonly(&CFG::c_FEE_PER_KB_OLD));
    cfg_ut.set("FEE_PER_KB",                                            sol::readonly(&CFG::c_FEE_PER_KB));
    cfg_ut.set("FEE_PER_BYTE",                                          sol::readonly(&CFG::c_FEE_PER_BYTE));
    cfg_ut.set("DYNAMIC_FEE_PER_KB_BASE_FEE",                           sol::readonly(&CFG::c_DYNAMIC_FEE_PER_KB_BASE_FEE));
    cfg_ut.set("DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD",                  sol::readonly(&CFG::c_DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD));
    cfg_ut.set("DYNAMIC_FEE_PER_KB_BASE_FEE_V5",                        sol::readonly(&CFG::c_DYNAMIC_FEE_PER_KB_BASE_FEE_V5));
    cfg_ut.set("DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT",              sol::readonly(&CFG::c_DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT));
    cfg_ut.set("ORPHANED_BLOCKS_MAX_COUNT",                             sol::readonly(&CFG::c_ORPHANED_BLOCKS_MAX_COUNT));
    cfg_ut.set("DIFFICULTY_TARGET_V2",                                  sol::readonly(&CFG::c_DIFFICULTY_TARGET_V2));
    cfg_ut.set("DIFFICULTY_TARGET_V1",                                  sol::readonly(&CFG::c_DIFFICULTY_TARGET_V1));
    cfg_ut.set("DIFFICULTY_WINDOW",                                     sol::readonly(&CFG::c_DIFFICULTY_WINDOW));
    cfg_ut.set("DIFFICULTY_LAG",                                        sol::readonly(&CFG::c_DIFFICULTY_LAG));
    cfg_ut.set("DIFFICULTY_CUT",                                        sol::readonly(&CFG::c_DIFFICULTY_CUT));
    cfg_ut.set("DIFFICULTY_BLOCKS_COUNT",                               sol::readonly(&CFG::c_DIFFICULTY_BLOCKS_COUNT));
    cfg_ut.set("CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1",         sol::readonly(&CFG::c_CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1));
    cfg_ut.set("CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2",         sol::readonly(&CFG::c_CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2));
    cfg_ut.set("CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS",             sol::readonly(&CFG::c_CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS));
    cfg_ut.set("DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN",                   sol::readonly(&CFG::c_DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN));
    cfg_ut.set("BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT",                sol::readonly(&CFG::c_BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT));
    cfg_ut.set("BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT",                    sol::readonly(&CFG::c_BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT));
    cfg_ut.set("BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4",             sol::readonly(&CFG::c_BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4));
    cfg_ut.set("BLOCKS_SYNCHRONIZING_DEFAULT_COUNT",                    sol::readonly(&CFG::c_BLOCKS_SYNCHRONIZING_DEFAULT_COUNT));
    cfg_ut.set("BLOCKS_SYNCHRONIZING_MAX_COUNT",                        sol::readonly(&CFG::c_BLOCKS_SYNCHRONIZING_MAX_COUNT));
    cfg_ut.set("CRYPTONOTE_MEMPOOL_TX_LIVETIME",                        sol::readonly(&CFG::c_CRYPTONOTE_MEMPOOL_TX_LIVETIME));
    cfg_ut.set("CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME",         sol::readonly(&CFG::c_CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME));
    cfg_ut.set("CRYPTONOTE_DANDELIONPP_STEMS",                          sol::readonly(&CFG::c_CRYPTONOTE_DANDELIONPP_STEMS));
    cfg_ut.set("CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY",              sol::readonly(&CFG::c_CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY));
    cfg_ut.set("CRYPTONOTE_DANDELIONPP_MIN_EPOCH",                      sol::readonly(&CFG::c_CRYPTONOTE_DANDELIONPP_MIN_EPOCH));
    cfg_ut.set("CRYPTONOTE_DANDELIONPP_EPOCH_RANGE",                    sol::readonly(&CFG::c_CRYPTONOTE_DANDELIONPP_EPOCH_RANGE));
    cfg_ut.set("CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE",                  sol::readonly(&CFG::c_CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE));
    cfg_ut.set("CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE",                sol::readonly(&CFG::c_CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE));
    cfg_ut.set("CRYPTONOTE_NOISE_MIN_EPOCH",                            sol::readonly(&CFG::c_CRYPTONOTE_NOISE_MIN_EPOCH));
    cfg_ut.set("CRYPTONOTE_NOISE_EPOCH_RANGE",                          sol::readonly(&CFG::c_CRYPTONOTE_NOISE_EPOCH_RANGE));
    cfg_ut.set("CRYPTONOTE_NOISE_MIN_DELAY",                            sol::readonly(&CFG::c_CRYPTONOTE_NOISE_MIN_DELAY));
    cfg_ut.set("CRYPTONOTE_NOISE_DELAY_RANGE",                          sol::readonly(&CFG::c_CRYPTONOTE_NOISE_DELAY_RANGE));
    cfg_ut.set("CRYPTONOTE_NOISE_BYTES",                                sol::readonly(&CFG::c_CRYPTONOTE_NOISE_BYTES));
    cfg_ut.set("CRYPTONOTE_NOISE_CHANNELS",                             sol::readonly(&CFG::c_CRYPTONOTE_NOISE_CHANNELS));
    cfg_ut.set("CRYPTONOTE_FORWARD_DELAY_BASE",                         sol::readonly(&CFG::c_CRYPTONOTE_FORWARD_DELAY_BASE));
    cfg_ut.set("CRYPTONOTE_FORWARD_DELAY_AVERAGE",                      sol::readonly(&CFG::c_CRYPTONOTE_FORWARD_DELAY_AVERAGE));
    cfg_ut.set("CRYPTONOTE_MAX_FRAGMENTS",                              sol::readonly(&CFG::c_CRYPTONOTE_MAX_FRAGMENTS));
    cfg_ut.set("COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT",           sol::readonly(&CFG::c_COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT));
    cfg_ut.set("COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT",              sol::readonly(&CFG::c_COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT));
    cfg_ut.set("MAX_RPC_CONTENT_LENGTH",                                sol::readonly(&CFG::c_MAX_RPC_CONTENT_LENGTH));
    cfg_ut.set("CRYPTONOTE_NAME",                                       sol::readonly(&CFG::c_CRYPTONOTE_NAME));
    cfg_ut.set("COIN_NAME",                                             sol::readonly(&CFG::c_COIN_NAME));
    cfg_ut.set("MILLICOIN_NAME",                                        sol::readonly(&CFG::c_MILLICOIN_NAME));
    cfg_ut.set("MICROCOIN_NAME",                                        sol::readonly(&CFG::c_MICROCOIN_NAME));
    cfg_ut.set("NANOCOIN_NAME",                                         sol::readonly(&CFG::c_NANOCOIN_NAME));
    cfg_ut.set("PICOCOIN_NAME",                                         sol::readonly(&CFG::c_PICOCOIN_NAME));
    cfg_ut.set("CRYPTONOTE_PRUNING_STRIPE_SIZE",                        sol::readonly(&CFG::c_CRYPTONOTE_PRUNING_STRIPE_SIZE));
    cfg_ut.set("CRYPTONOTE_PRUNING_LOG_STRIPES",                        sol::readonly(&CFG::c_CRYPTONOTE_PRUNING_LOG_STRIPES));
    cfg_ut.set("CRYPTONOTE_PRUNING_TIP_BLOCKS",                         sol::readonly(&CFG::c_CRYPTONOTE_PRUNING_TIP_BLOCKS));
    cfg_ut.set("MAX_TX_EXTRA_SIZE",                                     sol::readonly(&CFG::c_MAX_TX_EXTRA_SIZE));
    cfg_ut.set("MAX_TX_EXTRA_MSG_SIZE",                                 sol::readonly(&CFG::c_MAX_TX_EXTRA_MSG_SIZE));
    cfg_ut.set("MAX_TX_MSG_PRUNABLE_SIZE",                              sol::readonly(&CFG::c_MAX_TX_MSG_PRUNABLE_SIZE));
    cfg_ut.set("MSG_TX_AMOUNT",                                         sol::readonly(&CFG::c_MSG_TX_AMOUNT));
    cfg_ut.set("MSG_TX_EXTRA_TYPE",                                     sol::readonly(&CFG::c_MSG_TX_EXTRA_TYPE));
    cfg_ut.set("MSG_TX_EXTRA_CTRL",                                     sol::readonly(&CFG::c_MSG_TX_EXTRA_CTRL));
    cfg_ut.set("MSG_TX_EXTRA_USER",                                     sol::readonly(&CFG::c_MSG_TX_EXTRA_USER));
    cfg_ut.set("MSG_TX_EXTRA_FREQ_0",                                   sol::readonly(&CFG::c_MSG_TX_EXTRA_FREQ_0));
    cfg_ut.set("ATOMIC_SWAP_MSG_TX_EXTRA_TYPE",                         sol::readonly(&CFG::c_ATOMIC_SWAP_MSG_TX_EXTRA_TYPE));
    cfg_ut.set("ATOMIC_SWAP_HASH_X_UNLOCK_TIME",                        sol::readonly(&CFG::c_ATOMIC_SWAP_HASH_X_UNLOCK_TIME));
    cfg_ut.set("CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX",               sol::readonly(&CFG::c_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX));
    cfg_ut.set("CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX",    sol::readonly(&CFG::c_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX));
    cfg_ut.set("CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX",       sol::readonly(&CFG::c_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX));
    cfg_ut.set("CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX",            sol::readonly(&CFG::c_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX));
    cfg_ut.set("P2P_DEFAULT_PORT",                                      sol::readonly(&CFG::c_P2P_DEFAULT_PORT));
    cfg_ut.set("RPC_DEFAULT_PORT",                                      sol::readonly(&CFG::c_RPC_DEFAULT_PORT));
    cfg_ut.set("ZMQ_RPC_DEFAULT_PORT",                                  sol::readonly(&CFG::c_ZMQ_RPC_DEFAULT_PORT));
    cfg_ut.set("NETWORK_ID",                                            sol::readonly(&CFG::c_NETWORK_ID));
    cfg_ut.set("GENESIS_TX",                                            sol::readonly(&CFG::c_GENESIS_TX));
    cfg_ut.set("GENESIS_NONCE",                                         sol::readonly(&CFG::c_GENESIS_NONCE));
    cfg_ut.set("GENESIS_TIMESTAMP",                                     sol::readonly(&CFG::c_GENESIS_TIMESTAMP));
                                                                                                                                   
    cfg_ut.set("testnet.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX",              sol::readonly(&CFG::c_t_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX));
    cfg_ut.set("testnet.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX",   sol::readonly(&CFG::c_t_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX));
    cfg_ut.set("testnet.CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX",      sol::readonly(&CFG::c_t_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX));
    cfg_ut.set("testnet.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX",           sol::readonly(&CFG::c_t_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX));
    cfg_ut.set("testnet.P2P_DEFAULT_PORT",                                     sol::readonly(&CFG::c_t_P2P_DEFAULT_PORT));
    cfg_ut.set("testnet.RPC_DEFAULT_PORT",                                     sol::readonly(&CFG::c_t_RPC_DEFAULT_PORT));
    cfg_ut.set("testnet.ZMQ_RPC_DEFAULT_PORT",                                 sol::readonly(&CFG::c_t_ZMQ_RPC_DEFAULT_PORT));
    cfg_ut.set("testnet.NETWORK_ID",                                           sol::readonly(&CFG::c_t_NETWORK_ID));
    cfg_ut.set("testnet.GENESIS_TX",                                           sol::readonly(&CFG::c_t_GENESIS_TX));
    cfg_ut.set("testnet.GENESIS_NONCE",                                        sol::readonly(&CFG::c_t_GENESIS_NONCE));
    cfg_ut.set("testnet.GENESIS_TIMESTAMP",                                    sol::readonly(&CFG::c_t_GENESIS_TIMESTAMP));
                                                                                                                                           
    cfg_ut.set("stagenet.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX",             sol::readonly(&CFG::c_s_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX));
    cfg_ut.set("stagenet.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX",  sol::readonly(&CFG::c_s_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX));
    cfg_ut.set("stagenet.CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX",     sol::readonly(&CFG::c_s_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX));
    cfg_ut.set("stagenet.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX",          sol::readonly(&CFG::c_s_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX));
    cfg_ut.set("stagenet.P2P_DEFAULT_PORT",                                    sol::readonly(&CFG::c_s_P2P_DEFAULT_PORT));
    cfg_ut.set("stagenet.RPC_DEFAULT_PORT",                                    sol::readonly(&CFG::c_s_RPC_DEFAULT_PORT));
    cfg_ut.set("stagenet.ZMQ_RPC_DEFAULT_PORT",                                sol::readonly(&CFG::c_s_ZMQ_RPC_DEFAULT_PORT));
    cfg_ut.set("stagenet.NETWORK_ID_",                                         sol::readonly(&CFG::c_s_NETWORK_ID));
    cfg_ut.set("stagenet.GENESIS_TX",                                          sol::readonly(&CFG::c_s_GENESIS_TX));
    cfg_ut.set("stagenet.GENESIS_NONCE",                                       sol::readonly(&CFG::c_s_GENESIS_NONCE));
    cfg_ut.set("stagenet.GENESIS_TIMESTAMP",                                   sol::readonly(&CFG::c_s_GENESIS_TIMESTAMP));

    cryptonote["config"] = cfg;
  }

  bool simple::reg(sol::state_view& lua, simple *S)
  {
    lldb::lua_Reg(lua, S->root_path_);
    zyre::reg(lua, S->lua_mx_);

    lua.script(R"(tools = {}
                  crypto = {}
                  epee = {}
                  cryptonote = {})");

    auto tools = lua.get<sol::table>("tools");
    auto sepee = lua.get<sol::table>("epee");
    auto crypto = lua.get<sol::table>("crypto");
    auto cryptonote = lua.get<sol::table>("cryptonote");

    lua_json_reg(tools, lua);
    reg_config(cryptonote);

    auto int64_ctor0 = [](int a) { return I64{a}; };
    auto int64_ctor1 = [](sol::object, int a) { return I64{a}; };
    auto int64_ctor0_d = [](double a) { return I64{int64_t(a)}; };
    auto int64_ctor1_d = [](sol::object, double a) { return I64{int64_t(a)}; };
    auto int64_ctor0_i = [](const I64& a) { return I64{int64_t(a.v)}; };
    auto int64_ctor1_i = [](sol::object, const I64& a) { return I64{int64_t(a.v)}; };
    auto int64_ctor0_u = [](const I64& a) { return I64{a.v}; };
    auto int64_ctor1_u = [](sol::object, const I64& a) { return I64{a.v}; };
    auto int64_ctor0_s = [](const std::string& a) {
          I64 u;
          std::stringstream ss(a);
          ss >> u.v;
          return u;
        };
    auto int64_ctor1_s = [](sol::object, const std::string& a) {
          I64 u;
          std::stringstream ss(a);
          ss >> u.v;
          return u;
        };
    tools.new_usertype<I64>("int64_t",
      sol::meta_function::construct,
      sol::factories(int64_ctor0, int64_ctor1, int64_ctor0_d, int64_ctor1_d, int64_ctor0_i, int64_ctor1_i, int64_ctor0_u, int64_ctor1_u, int64_ctor0_s, int64_ctor1_s),
      sol::call_constructor,
      sol::factories(int64_ctor0, int64_ctor0_d, int64_ctor0_i, int64_ctor0_u, int64_ctor0_s),
      sol::meta_function::addition, sol::overload(
                  [](const I64& u, const I64& r) { return I64{u.v + r.v}; },
                  [](const I64& u, const U64& r) { return I64{u.v + int64_t(r.v)}; },
                  [](const I64& u, double r) { return I64{u.v + int64_t(r)}; },
                  [](const I64& u, int r) { return I64{u.v + int64_t(r)}; }),
      sol::meta_function::subtraction, sol::overload(
                  [](const I64& u, const I64& r) { return I64{u.v - r.v}; },
                  [](const I64& u, const U64& r) { return I64{u.v - int64_t(r.v)}; },
                  [](const I64& u, double r) { return I64{u.v - int64_t(r)}; },
                  [](const I64& u, int r) { return I64{u.v - int64_t(r)}; }),
      sol::meta_function::multiplication, sol::overload(
                  [](const I64& u, const I64& r) { return I64{u.v * r.v}; },
                  [](const I64& u, const U64& r) { return I64{u.v * int64_t(r.v)}; },
                  [](const I64& u, double r) { return I64{u.v * int64_t(r)}; },
                  [](const I64& u, int r) { return I64{u.v * int64_t(r)}; }),
      sol::meta_function::division, sol::overload(
                  [](const I64& u, const I64& r) { return I64{u.v / r.v}; },
                  [](const I64& u, const U64& r) { return I64{u.v / int64_t(r.v)}; },
                  [](const I64& u, double r) { return I64{u.v / int64_t(r)}; },
                  [](const I64& u, int r) { return I64{u.v / int64_t(r)}; }),
      sol::meta_function::equal_to, [](const I64& u, const I64& r) { return u.v == r.v; },
      sol::meta_function::less_than, [](const I64& u, const I64& r) { return u.v < r.v; },
      sol::meta_function::less_than_or_equal_to, [](const I64& u, const I64& r) { return u.v <= r.v; },
      sol::meta_function::bitwise_left_shift, [](const I64& u, int r) { return I64{u.v << r}; },
      sol::meta_function::bitwise_right_shift, [](const I64& u, int r) { return I64{u.v >> r}; },
      sol::meta_function::bitwise_not, [](const I64& u) { return I64{!u.v}; },
      sol::meta_function::bitwise_and, [](const I64& u, const I64& r) { return I64{u.v & r.v}; },
      sol::meta_function::bitwise_or, [](const I64& u, const I64& r) { return I64{u.v | r.v}; },
      sol::meta_function::bitwise_xor, [](const I64& u, const I64& r) { return I64{u.v ^ r.v}; },
      sol::meta_function::to_string, [](const I64& u) { std::stringstream ss; ss << u.v; return ss.str(); },
      "max", []() { return I64{std::numeric_limits<int64_t>::max()}; },
      "min", []() { return I64{std::numeric_limits<int64_t>::min()}; },
      "convert_to_u64", [](const I64& u) { return U64{uint64_t(u.v)}; },
      "number", [](const I64& u) { return double(u.v); },
      "data", [](const I64& u) { return std::string((const char *)&u, (const char *)&u + sizeof(I64)); },
      "to_data", [](const I64& u) { return std::string((const char *)&u, (const char *)&u + sizeof(I64)); },
      "from_data", [&lua](const std::string& a) {
        I64 u;
        if(a.size() != sizeof(I64)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(lua,"incorrect blob data: %s", b.c_str());
        }
        else
          memcpy(&u, a.data(), sizeof(I64));
        return u;
      },
      "print_money", [](const I64& u) { return cryptonote::print_money(uint64_t(u.v)); },
      "to_hex", [](const I64& u) {
        epee::span<const std::uint8_t> s{reinterpret_cast<const std::uint8_t*>(&u), sizeof(u)};
        return epee::to_hex::string(s);
      }
    );

    auto uint64_ctor0 = [](int a) { return U64{uint64_t(a)}; };
    auto uint64_ctor1 = [](sol::object, int a) { return U64{uint64_t(a)}; };
    auto uint64_ctor0_d = [](double a) { return U64{uint64_t(a)}; };
    auto uint64_ctor1_d = [](sol::object, double a) { return U64{uint64_t(a)}; };
    auto uint64_ctor0_u = [](const U64& a) { return U64{uint64_t(a.v)}; };
    auto uint64_ctor1_u = [](sol::object, const U64& a) { return U64{uint64_t(a.v)}; };
    auto uint64_ctor0_i = [](const I64& a) { return U64{uint64_t(a.v)}; };
    auto uint64_ctor1_i = [](sol::object, const I64& a) { return U64{uint64_t(a.v)}; };
    auto uint64_ctor0_s = [](const std::string& a) {
          U64 u;
          std::stringstream ss(a);
          ss >> u.v;
          return u;
        };
    auto uint64_ctor1_s = [](sol::object, const std::string& a) {
          U64 u;
          std::stringstream ss(a);
          ss >> u.v;
          return u;
        };
    tools.new_usertype<U64>("uint64_t",
      sol::meta_function::construct,
      sol::factories(uint64_ctor0, uint64_ctor1, uint64_ctor0_d, uint64_ctor1_d, uint64_ctor0_u, uint64_ctor1_u, uint64_ctor0_i, uint64_ctor1_i, uint64_ctor0_s, uint64_ctor1_s),
      sol::call_constructor,
      sol::factories(uint64_ctor0, uint64_ctor0_d, uint64_ctor0_u, uint64_ctor0_i, uint64_ctor0_s),
      sol::meta_function::addition, sol::overload(
        [](const U64& u, const I64& r) { return U64{u.v + uint64_t(r.v)}; },
        [](const U64& u, const U64& r) { return U64{u.v + r.v}; },
        [](const U64& u, double r) { return U64{u.v + uint64_t(r)}; },
        [](const U64& u, int r) { return U64{u.v + uint64_t(r)}; }),
      sol::meta_function::subtraction, sol::overload(
        [](const U64& u, const I64& r) { return U64{u.v - uint64_t(r.v)}; },
        [](const U64& u, const U64& r) { return U64{u.v - r.v}; },
        [](const U64& u, double r) { return U64{u.v - uint64_t(r)}; },
        [](const U64& u, int r) { return U64{u.v - uint64_t(r)}; }),
      sol::meta_function::multiplication, sol::overload(
        [](const U64& u, const I64& r) { return U64{u.v * uint64_t(r.v)}; },
        [](const U64& u, const U64& r) { return U64{u.v * r.v}; },
        [](const U64& u, double r) { return U64{u.v * uint64_t(r)}; },
        [](const U64& u, int r) { return U64{u.v * uint64_t(r)}; }),
      sol::meta_function::division, sol::overload(
        [](const U64& u, const I64& r) { return U64{u.v / uint64_t(r.v)}; },
        [](const U64& u, const U64& r) { return U64{u.v / r.v}; },
        [](const U64& u, double r) { return U64{u.v / uint64_t(r)}; },
        [](const U64& u, int r) { return U64{u.v / uint64_t(r)}; }),
      sol::meta_function::equal_to, [](const U64& u, const U64& r) { return U64{u.v == r.v}; },
      sol::meta_function::less_than, [](const U64& u, const U64& r) { return u.v < r.v; },
      sol::meta_function::less_than_or_equal_to, [](const U64& u, const U64& r) { return u.v <= r.v; },
      sol::meta_function::bitwise_left_shift, [](const U64& u, int r) { return U64{u.v << r}; },
      sol::meta_function::bitwise_right_shift, [](const U64& u, int r) { return U64{u.v >> r}; },
      sol::meta_function::bitwise_not, [](const U64& u) { return U64{!u.v}; },
      sol::meta_function::bitwise_and, [](const U64& u, const U64& r) { return U64{u.v & r.v}; },
      sol::meta_function::bitwise_or, [](const U64& u, const U64& r) { return U64{u.v | r.v}; },
      sol::meta_function::bitwise_xor, [](const U64& u, const U64& r) { return U64{u.v ^ r.v}; },
      sol::meta_function::to_string, [](const U64& u) { std::stringstream ss; ss << u.v; return ss.str(); },
      "max", []() { return U64{std::numeric_limits<uint64_t>::max()}; },
      "min", []() { return U64{std::numeric_limits<uint64_t>::min()}; },
      "convert_to_i64", [](const U64& u) { return I64{int64_t(u.v)}; },
      "number", [](const U64& u) { return double(u.v); },
      "data", [](const U64& u) { return std::string((const char *)&u, (const char *)&u + sizeof(U64)); },
      "to_data", [](const U64& u) { return std::string((const char *)&u, (const char *)&u + sizeof(U64)); },
      "from_data", [&lua](const std::string& a) {
        U64 u;
        if(a.size() != sizeof(U64)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(lua,"incorrect blob data: %s", b.c_str());
        }
        else
          memcpy(&u, a.data(), sizeof(U64));
        return u;
      },
      "print_money", [](const U64& u) { return cryptonote::print_money(u.v); },
      "to_hex", [](const U64& u) {
        epee::span<const std::uint8_t> s{reinterpret_cast<const std::uint8_t*>(&u), sizeof(u)};
        return epee::to_hex::string(s);
      }
    );

    auto hash_ctor0 = []() { return crypto::hash{}; };
    auto hash_ctor1 = [](sol::object) { return crypto::hash{}; };
    auto hash_ctor0_h = [](const crypto::hash& h) { return h; };
    auto hash_ctor1_h = [](sol::object, const crypto::hash& h) { return h; };
    auto hash_ctor0_s = [&lua](const std::string& a)
    {
      crypto::hash u;
      if(a.size() == crypto::HASH_SIZE) {
        if(!cryptonote::t_serializable_object_from_blob(u, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(lua,"incorrect blob data: %s", b.c_str());
        }
      }
      else
      {
        if(!epee::string_tools::hex_to_pod(a, u))
          luaL_error(lua,"incorrect hex string: %s", a.c_str());
      }
      return u;
    };
    auto hash_ctor1_s = [&hash_ctor0_s](sol::object, const std::string& a)
      { return hash_ctor0_s(a); };

    crypto.new_usertype<crypto::hash>("hash",
      sol::meta_function::construct,
      sol::factories(hash_ctor0, hash_ctor1, hash_ctor0_h, hash_ctor1_h, hash_ctor0_s, hash_ctor1_s),
      sol::call_constructor,
      sol::factories(hash_ctor0, hash_ctor0_h, hash_ctor0_s),
      sol::meta_function::to_string, [](const crypto::hash& h) { return epee::string_tools::pod_to_hex(h); },
      "data", [](const crypto::hash& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "to_data", [](const crypto::hash& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "from_data", [](crypto::hash& h, const std::string& a, lua_State* L) {
        if(a.size() != crypto::HASH_SIZE || !cryptonote::t_serializable_object_from_blob(h, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(L,"incorrect blob data: %s", b.c_str());
        }
      },
      "to_hex", [](const crypto::hash& h) { return epee::string_tools::pod_to_hex(h); },
      "from_hex", [](crypto::hash& h, const std::string& src, lua_State* L) {
         if(!epee::string_tools::hex_to_pod(src, h))
           luaL_error(L,"incorrect hex string: %s", src.c_str());
      },
      sol::meta_function::equal_to, [](const crypto::hash& l, const crypto::hash& r) { return l == r; }
    );

    auto hash8_ctor0 = []() { return crypto::hash8{}; };
    auto hash8_ctor1 = [](sol::object) { return crypto::hash8{}; };
    auto hash8_ctor0_h = [](const crypto::hash8& h) { return h; };
    auto hash8_ctor1_h = [](sol::object, const crypto::hash8& h) { return h; };
    auto hash8_ctor0_s = [&lua](const std::string& a)
    {
      crypto::hash8 u;
      if(a.size() == 8) {
        if(!cryptonote::t_serializable_object_from_blob(u, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(lua,"incorrect blob data: %s", b.c_str());
        }
      }
      else
      {
        if(!epee::string_tools::hex_to_pod(a, u))
          luaL_error(lua,"incorrect hex string: %s", a.c_str());
      }
      return u;
    };
    auto hash8_ctor1_s = [&hash8_ctor0_s](sol::object, const std::string& a)
      { return hash8_ctor0_s(a); };

    crypto.new_usertype<crypto::hash8>("hash8",
      sol::meta_function::construct,
      sol::factories(hash8_ctor0, hash8_ctor1, hash8_ctor0_h, hash8_ctor1_h, hash8_ctor0_s, hash8_ctor1_s),
      sol::call_constructor,
      sol::factories(hash8_ctor0, hash8_ctor0_h, hash8_ctor0_s),
      sol::meta_function::to_string, [](const crypto::hash8& h) { return epee::string_tools::pod_to_hex(h); },
      "data", [](const crypto::hash8& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "to_data", [](const crypto::hash8& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "from_data", [](crypto::hash8& h, const std::string& a, lua_State* L) {
        if(a.size() != 8 || !cryptonote::t_serializable_object_from_blob(h, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(L,"incorrect blob data: %s", b.c_str());
        }
      },
      "to_hex", [](const crypto::hash8& h) { return epee::string_tools::pod_to_hex(h); },
      "from_hex", [](crypto::hash8& h, const std::string& src, lua_State* L) {
         if(!epee::string_tools::hex_to_pod(src, h))
           luaL_error(L,"incorrect hex string: %s", src.c_str());
      },
      sol::meta_function::equal_to, [](const crypto::hash8& l, const crypto::hash8& r) { return l == r; }
    );

    auto pkey_ctor0 = []() { return crypto::public_key{}; };
    auto pkey_ctor1 = [](sol::object) { return crypto::public_key{}; };
    auto pkey_ctor0_h = [](const crypto::public_key& h) { return h; };
    auto pkey_ctor1_h = [](sol::object, const crypto::public_key& h) { return h; };
    auto pkey_ctor0_s = [&lua](const std::string& a)
    {
      crypto::public_key u;
      if(a.size() == 32) {
        if(!cryptonote::t_serializable_object_from_blob(u, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(lua,"incorrect blob data: %s", b.c_str());
        }
      }
      else
      {
        if(!epee::string_tools::hex_to_pod(a, u))
          luaL_error(lua,"incorrect hex string: %s", a.c_str());
      }
      return u;
    };
    auto pkey_ctor1_s = [&pkey_ctor0_s](sol::object, const std::string& a)
      { return pkey_ctor0_s(a); };

    crypto.new_usertype<crypto::public_key>("public_key",
      sol::meta_function::construct,
      sol::factories(pkey_ctor0, pkey_ctor1, pkey_ctor0_h, pkey_ctor1_h, pkey_ctor0_s, pkey_ctor1_s),
      sol::call_constructor,
      sol::factories(pkey_ctor0, pkey_ctor0_h, pkey_ctor0_s),
      sol::meta_function::to_string, [](const crypto::public_key& h) { return epee::string_tools::pod_to_hex(h); },
      "data", [](const crypto::public_key& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "to_data", [](const crypto::public_key& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "from_data", [](crypto::public_key& h, const std::string& a, lua_State* L) {
        if(a.size() != 32 || !cryptonote::t_serializable_object_from_blob(h, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(L,"incorrect blob data: %s", b.c_str());
        }
      },
      "to_hex", [](const crypto::public_key& k) { return epee::string_tools::pod_to_hex(k); },
      "from_hex", [](crypto::public_key& k, const std::string& src, lua_State* L) {
         if(!epee::string_tools::hex_to_pod(src, k))
           luaL_error(L,"incorrect hex string: %s", src.c_str());
      },
      sol::meta_function::equal_to, [](const crypto::public_key& l, const crypto::public_key& r) { return l == r; }
    );

    auto skey_ctor0 = []() { return crypto::secret_key{}; };
    auto skey_ctor1 = [](sol::object) { return crypto::secret_key{}; };
    auto skey_ctor0_h = [](const crypto::secret_key& h) { return h; };
    auto skey_ctor1_h = [](sol::object, const crypto::secret_key& h) { return h; };
    auto skey_ctor0_s = [&lua](const std::string& a) 
    {
      crypto::secret_key u;
      if(a.size() == 32) {
        if(!cryptonote::t_serializable_object_from_blob(u, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(lua,"incorrect blob data: %s", b.c_str());
        }
      }
      else
      {
        if(!epee::string_tools::hex_to_pod(a, u))
          luaL_error(lua,"incorrect hex string: %s", a.c_str());
      }
      return u;
    };
    auto skey_ctor1_s = [&skey_ctor0_s](sol::object, const std::string& a)
      { return skey_ctor0_s(a); };

    crypto.new_usertype<crypto::secret_key>("secret_key",
      sol::meta_function::construct,
      sol::factories(skey_ctor0, skey_ctor1, skey_ctor0_h, skey_ctor1_h, skey_ctor0_s, skey_ctor1_s),
      sol::call_constructor,
      sol::factories(skey_ctor0, skey_ctor0_h, skey_ctor0_s),
      sol::meta_function::to_string, [](const crypto::secret_key& k) { return epee::string_tools::pod_to_hex(k); },
      "data", [](const crypto::secret_key& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "to_data", [](const crypto::secret_key& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "from_data", [](crypto::secret_key& h, const std::string& a, lua_State* L) {
        if(a.size() != 32 || !cryptonote::t_serializable_object_from_blob(h, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(L,"incorrect blob data: %s", b.c_str());
        }
      },
      "to_hex", [](const crypto::secret_key& k) { return epee::string_tools::pod_to_hex(k); },
      "from_hex", [](crypto::secret_key& k, const std::string& src, lua_State* L) {
         if(!epee::string_tools::hex_to_pod(src, k))
           luaL_error(L,"incorrect hex string: %s", src.c_str());
      },
      sol::meta_function::equal_to, [](const crypto::secret_key& l, const crypto::secret_key& r) { return l == r; }
    );

    auto keyd_ctor0 = []() { return crypto::key_derivation{}; };
    auto keyd_ctor1 = [](sol::object) { return crypto::key_derivation{}; };
    auto keyd_ctor0_h = [](const crypto::key_derivation& h) { return h; };
    auto keyd_ctor1_h = [](sol::object, const crypto::key_derivation& h) { return h; };
    auto keyd_ctor0_s = [&lua](const std::string& a) 
    {
      crypto::key_derivation u;
      if(a.size() == 32) {
        if(!cryptonote::t_serializable_object_from_blob(u, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(lua,"incorrect blob data: %s", b.c_str());
        }
      }
      else
      {
        if(!epee::string_tools::hex_to_pod(a, u))
          luaL_error(lua,"incorrect hex string: %s", a.c_str());
      }
      return u;
    };
    auto keyd_ctor1_s = [&keyd_ctor0_s](sol::object, const std::string& a)
      { return keyd_ctor0_s(a); };

    crypto.new_usertype<crypto::key_derivation>("key_derivation",
      sol::meta_function::construct,
      sol::factories(keyd_ctor0, keyd_ctor1, keyd_ctor0_h, keyd_ctor1_h, keyd_ctor0_s, keyd_ctor1_s),
      sol::call_constructor,
      sol::factories(keyd_ctor0, keyd_ctor0_h, keyd_ctor0_s),
      sol::meta_function::to_string, [](const crypto::key_derivation& k) { return epee::string_tools::pod_to_hex(k); },
      "data", [](const crypto::key_derivation& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "to_data", [](const crypto::key_derivation& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "from_data", [](crypto::key_derivation& h, const std::string& a, lua_State* L) {
        if(a.size() != 32 || !cryptonote::t_serializable_object_from_blob(h, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(L,"incorrect blob data: %s", b.c_str());
        }
      },
      "to_hex", [](const crypto::key_derivation& k) { return epee::string_tools::pod_to_hex(k); },
      "from_hex", [](crypto::key_derivation& k, const std::string& src, lua_State* L) {
         if(!epee::string_tools::hex_to_pod(src, k))
           luaL_error(L,"incorrect hex string: %s", src.c_str());
      },
      sol::meta_function::equal_to, [](const crypto::key_derivation& l, const crypto::key_derivation& r) { return 0 == memcmp(&l, &r, sizeof(crypto::key_derivation)); }
    );


    auto sign_ctor0 = []() { return crypto::signature{}; };
    auto sign_ctor1 = [](sol::object) { return crypto::signature{}; };
    auto sign_ctor0_h = [](const crypto::signature& s) { return s; };
    auto sign_ctor1_h = [](sol::object, const crypto::signature& s) { return s; };
    auto sign_ctor0_s = [&lua](const std::string& a) 
    {
      crypto::signature s;
      if(a.size() == sizeof(crypto::signature)) {
        if(!cryptonote::t_serializable_object_from_blob(s, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(lua,"incorrect blob data: %s", b.c_str());
        }
      }
      else
      {
        if(!epee::string_tools::hex_to_pod(a, s))
          luaL_error(lua,"incorrect hex string: %s", a.c_str());
      }
      return s;
    };
    auto sign_ctor1_s = [&sign_ctor0_s](sol::object, const std::string& a)
      { return sign_ctor0_s(a); };

    crypto.new_usertype<crypto::signature>("signature",
      sol::meta_function::construct,
      sol::factories(sign_ctor0, sign_ctor1, sign_ctor0_h, sign_ctor1_h, sign_ctor0_s, sign_ctor1_s),
      sol::call_constructor,
      sol::factories(sign_ctor0, sign_ctor0_h, sign_ctor0_s),
      sol::meta_function::to_string, [](const crypto::signature& k) { return epee::string_tools::pod_to_hex(k); },
      "data", [](const crypto::signature& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "to_data", [](const crypto::signature& h)->std::string { return cryptonote::t_serializable_object_to_blob(h); },
      "from_data", [](crypto::signature& h, const std::string& a, lua_State* L) {
        if(a.size() != sizeof(crypto::signature) || !cryptonote::t_serializable_object_from_blob(h, a)) {
          auto b = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(L,"incorrect blob data: %s", b.c_str());
        }
      },
      "to_hex", [](const crypto::signature& k) { return epee::string_tools::pod_to_hex(k); },
      "from_hex", [](crypto::signature& k, const std::string& src, lua_State* L) {
         if(!epee::string_tools::hex_to_pod(src, k))
           luaL_error(L,"incorrect hex string: %s", src.c_str());
      },
      sol::meta_function::equal_to, [](const crypto::signature& l, const crypto::signature& r) { return 0 == memcmp(&l, &r, sizeof(crypto::signature)); }
    );

    crypto["cn_fast_hash"] = [](const std::string& buf)
    {
      crypto::hash hash;
      crypto::cn_fast_hash(buf.data(), buf.size(), hash);
      return hash;
    };

    crypto["generate_keys"] = [](sol::variadic_args args)
    {
      crypto::public_key pub;
      crypto::secret_key sec, recovery_key = crypto::secret_key();
      bool recover = false;

      lua_State *L = args.lua_state();
      int top = args.top();
      for(int n=args.stack_index(); n<=top; n++)
      {
        auto a = sol::stack_object(L, n);
        if(a.get_type() == sol::type::userdata)
          recovery_key = sol::stack_object(L, n).as<crypto::secret_key>();
        else if(a.get_type() == sol::type::boolean)
          recover = sol::stack_object(L, n).as<bool>();
      }

      crypto::generate_keys(pub, sec, recovery_key, recover);

      sol::variadic_results rc;
      rc.push_back({ L, sol::in_place_type<crypto::secret_key>, sec });
      rc.push_back({ L, sol::in_place_type<crypto::public_key>, pub });
      return rc;
    };

    crypto["generate_signature"] = [](const crypto::hash& hash, const crypto::public_key& pub, const crypto::secret_key& sec)
    {
      crypto::signature sign;
      crypto::generate_signature(hash, pub, sec, sign);
      return sign;
    };

    crypto["check_signature"] = [](const crypto::hash& hash, const crypto::public_key& pub, const crypto::signature& sign)
    {
      return crypto::check_signature(hash, pub, sign);
    };

    crypto["rand"] = [](int size, sol::this_state L)
    {
      if(size<0 || size>32768) {
        luaL_error(L,"incorrect string size(0 > size < 32768): %d", size);
        return std::string();
      }
      std::string buf;
      buf.resize(size);
      crypto::rand(size, (uint8_t*)buf.data());
      return buf;
    };

    sepee["to_hex"] = [](const std::string& data)
    {
      return epee::to_hex::string({(uint8_t*)data.data(), data.size()});
    };

    sepee["from_hex"] = [](const std::string& src, sol::this_state L)
    {
      std::string data; data.resize(src.size() / 2);
      if(!epee::from_hex::to_buffer(epee::to_mut_byte_span(data), src))
      {
        luaL_error(L,"incorrect hex string: %s", src.c_str());
        return std::string();
      }
      return data;
    };

    auto extra_ctor0 = [](){ return tx_extra_data_t(); };
    auto extra_ctor1 = [](sol::object){ return tx_extra_data_t(); };

    cryptonote.new_usertype<tx_extra_data_t>("tx_extra_data",
      sol::meta_function::construct, extra_ctor0,
      sol::call_constructor, extra_ctor1,
      sol::meta_function::to_string, [](const tx_extra_data_t& e) {
        return epee::to_hex::string({ e.data.data(), e.data.size() });
      },
      "length", [](tx_extra_data_t& e) { return e.data.size(); },
      "get_x", [](tx_extra_data_t& e, sol::this_state L) {
        cryptonote::tx_extra_atomic_swap_x x;
        bool ok = cryptonote::get_atomic_swap_x_from_extra(e.data, x);
        sol::variadic_results rc;
        rc.push_back({ L, sol::in_place_type<bool>, ok });
        rc.push_back({ L, sol::in_place_type<std::string>, x.data });
        return rc;
      },
      "set_x", [](tx_extra_data_t& e, const std::string& x) {
        return cryptonote::set_atomic_swap_x_to_extra(e.data, {x});
      },
      "get_hash_x", [](tx_extra_data_t& e, sol::this_state L) {
        cryptonote::tx_extra_atomic_swap_hash_x hx;
        bool ok = cryptonote::get_atomic_swap_hash_x_from_extra(e.data, hx);
        sol::variadic_results rc;
        rc.push_back({ L, sol::in_place_type<bool>, ok });
        rc.push_back({ L, sol::in_place_type<crypto::hash>, hx.hash });
        rc.push_back({ L, sol::in_place_type<U64>, U64{hx.unlock_time} });
        return rc;
      },
      "set_hash_x", [](tx_extra_data_t& e, const crypto::hash& hash, const U64& unlock_time) {
        return cryptonote::set_atomic_swap_hash_x_to_extra(e.data, {hash, unlock_time.v});
      },
      "get_pubkey_x", [](tx_extra_data_t& e, sol::this_state L) {
        cryptonote::tx_extra_atomic_swap_pubkey_x px;
        bool ok = cryptonote::get_atomic_swap_pubkey_x_from_extra(e.data, px);
        sol::variadic_results rc;
        rc.push_back({ L, sol::in_place_type<bool>, ok });
        rc.push_back({ L, sol::in_place_type<crypto::public_key>, px.pub_key });
        return rc;
      },
      "set_pubkey_x", [](tx_extra_data_t& e, const crypto::public_key& pub_key) {
        return cryptonote::set_atomic_swap_pubkey_x_to_extra(e.data, {pub_key});
      },
      "get_pubkey_t", [](tx_extra_data_t& e, sol::this_state L) {
        cryptonote::tx_extra_atomic_swap_pubkey_t pt;
        bool ok = cryptonote::get_atomic_swap_pubkey_t_from_extra(e.data, pt);
        sol::variadic_results rc;
        rc.push_back({ L, sol::in_place_type<bool>, ok });
        rc.push_back({ L, sol::in_place_type<crypto::public_key>, pt.pub_key });
        return rc;
      },
      "set_pubkey_t", [](tx_extra_data_t& e, const crypto::public_key& pub_key) {
        return cryptonote::set_atomic_swap_pubkey_t_to_extra(e.data, {pub_key});
      },
      "get_sign_x", [](tx_extra_data_t& e, sol::this_state L) {
        cryptonote::tx_extra_atomic_swap_sign_x s;
        bool ok = cryptonote::get_atomic_swap_sign_x_from_extra(e.data, s);
        sol::variadic_results rc;
        rc.push_back({ L, sol::in_place_type<bool>, ok });
        rc.push_back({ L, sol::in_place_type<crypto::signature>, s.sign });
        return rc;
      },
      "set_sign_x", [](tx_extra_data_t& e, const crypto::signature& sign) {
        return cryptonote::set_atomic_swap_sign_x_to_extra(e.data, {sign});
      },
      "get_sign_t", [](tx_extra_data_t& e, sol::this_state L) {
        cryptonote::tx_extra_atomic_swap_sign_t s;
        bool ok = cryptonote::get_atomic_swap_sign_t_from_extra(e.data, s);
        sol::variadic_results rc;
        rc.push_back({ L, sol::in_place_type<bool>, ok });
        rc.push_back({ L, sol::in_place_type<crypto::signature>, s.sign });
        return rc;
      },
      "set_sign_t", [](tx_extra_data_t& e, const crypto::signature& sign) {
        return cryptonote::set_atomic_swap_sign_t_to_extra(e.data, {sign});
      },
      "to_hex", [](tx_extra_data_t& e) { return epee::to_hex::string({e.data.data(), e.data.size()}); },
      "from_hex", [](tx_extra_data_t& e, const std::string& src, sol::this_state L) {
         if(!epee::from_hex::to_buffer(epee::to_mut_byte_span(e.data), src))
         {
           luaL_error(L,"incorrect hex string: %s", src.c_str());
           return false;
         }
         return true;
      }
    );

    auto tx_ctor0 = [](){ return cryptonote::transaction(); };
    auto tx_ctor1 = [](sol::object){ return cryptonote::transaction(); };

    cryptonote.new_usertype<cryptonote::transaction>("transaction",
      sol::meta_function::construct, tx_ctor0,
      sol::call_constructor, tx_ctor1,
      sol::meta_function::to_string, [](cryptonote::transaction& tx) { return cryptonote::obj_to_json_str(tx); },
      "to_blob", [](const cryptonote::transaction& tx) { return cryptonote::tx_to_blob(tx); },
      "to_hex", [](const cryptonote::transaction& tx) { return epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(tx)); },
      "to_json", [](cryptonote::transaction& tx) { return cryptonote::obj_to_json_str(tx); },
      "to_table", [](cryptonote::transaction& tx) {
         msgpack_out out;
         tools::json2pack(cryptonote::obj_to_json_str(tx), out.data);
         return out;
      },
      "txid", sol::readonly_property([](const cryptonote::transaction& tx) { return cryptonote::get_transaction_hash(tx); }),
      "version", sol::readonly_property([](const cryptonote::transaction& tx) { return U64{tx.version}; }),
      "unlock_time", sol::readonly_property([](const cryptonote::transaction& tx) { return U64{tx.unlock_time}; }),
      "extra", sol::readonly_property([](const cryptonote::transaction& tx) { return tx_extra_data_t{tx.extra}; })
    );

    cryptonote.new_usertype<cryptonote::transaction_prefix>("transaction_prefix",
      sol::meta_function::to_string, [](cryptonote::transaction_prefix& tx) { return cryptonote::obj_to_json_str(tx); },
      "to_json", [](cryptonote::transaction_prefix& tx) { return cryptonote::obj_to_json_str(tx); },
      "to_table", [](cryptonote::transaction_prefix& tx) {
         msgpack_out out;
         tools::json2pack(cryptonote::obj_to_json_str(tx), out.data);
         return out;
      },
      "version", [](const cryptonote::transaction_prefix& tx) { return U64{tx.version}; },
      "unlock_time", sol::readonly_property([](const cryptonote::transaction& tx) { return U64{tx.unlock_time}; }),
      "extra", sol::readonly_property([](const cryptonote::transaction_prefix& tx) { return tx_extra_data_t{tx.extra}; })
    );

    auto addr_ctor0 = []() { return cryptonote::account_public_address{}; };
    auto addr_ctor1 = [](sol::object) { return cryptonote::account_public_address{}; };
    auto addr_ctor0_h = [](const cryptonote::account_public_address& a) { return a; };
    auto addr_ctor1_h = [](sol::object, const cryptonote::account_public_address& a) { return a; };
    auto addr_ctor0_s = [&lua](const std::string& a) 
    {
      cryptonote::account_public_address u;
      if(a.size() == sizeof(cryptonote::account_public_address))
      {
        memcpy(&u, a.data(), sizeof(cryptonote::account_public_address));
      }
      else
      {
        if(a.size() != 128)
          luaL_error(lua,"incorrect len: %s of  hex string: %s", a.size(), a.c_str());
        if(!epee::string_tools::hex_to_pod(a.substr(0, 64), u.m_spend_public_key))
          luaL_error(lua,"incorrect hex string: %s", a.c_str());
        if(!epee::string_tools::hex_to_pod(a.substr(64, 64), u.m_view_public_key))
          luaL_error(lua,"incorrect hex string: %s", a.c_str());
      }
      return u;
    };
    auto addr_ctor1_s = [&keyd_ctor0_s](sol::object, const std::string& a)
      { return keyd_ctor0_s(a); };

    cryptonote.new_usertype<cryptonote::account_public_address>("account_public_address",
      sol::meta_function::construct,
      sol::factories(addr_ctor0, addr_ctor1, addr_ctor0_h, addr_ctor1_h, addr_ctor0_s, addr_ctor1_s),
      sol::call_constructor,
      sol::factories(addr_ctor0, addr_ctor0_h, addr_ctor0_s),
      "m_spend_public_key", &cryptonote::account_public_address::m_spend_public_key,
      "m_view_public_key", &cryptonote::account_public_address::m_view_public_key,
      "data", [](const cryptonote::account_public_address& a) {
        return std::string((const char *)&a, ((const char *)&a) + sizeof(cryptonote::account_public_address));
      },
      "to_data", [](const cryptonote::account_public_address& a) {
        return std::string((const char *)&a, ((const char *)&a) + sizeof(cryptonote::account_public_address));
      },
      "from_data", [](cryptonote::account_public_address& u, const std::string& a, lua_State* L) {
        if(a.size() != sizeof(cryptonote::account_public_address))
        {
          std::string e = epee::to_hex::string({(uint8_t*)a.data(), a.size()});
          luaL_error(L, "incorrect blob data: %s", e.c_str());
          return;
        }
        memcpy(&u, a.data(), sizeof(cryptonote::account_public_address));
      },
      "to_hex", [](const cryptonote::account_public_address& a)
        { return epee::string_tools::pod_to_hex(a.m_spend_public_key) + epee::string_tools::pod_to_hex(a.m_view_public_key); },
      "from_hex", [](cryptonote::account_public_address& a, const std::string& s, lua_State* L) {
        if(s.size() != 128)
          luaL_error(L,"incorrect len: %s of  hex string: %s", s.size(), s.c_str());
        if(!epee::string_tools::hex_to_pod(s.substr(0, 64), a.m_spend_public_key))
          luaL_error(L,"incorrect hex string: %s", s.c_str());
        if(!epee::string_tools::hex_to_pod(s.substr(64, 64), a.m_view_public_key))
          luaL_error(L,"incorrect hex string: %s", s.c_str());
      },
      sol::meta_function::equal_to, [](const cryptonote::account_public_address& l, const cryptonote::account_public_address& r) { return l == r; }
    );

    tools.new_usertype<wallet2::address_book_row>("address_book_row",
      "m_address",        &wallet2::address_book_row::m_address,
      "m_payment_id",     &wallet2::address_book_row::m_payment_id,
      "m_description",    &wallet2::address_book_row::m_description,
      "m_is_subaddress",  &wallet2::address_book_row::m_is_subaddress,
      "m_has_payment_id", &wallet2::address_book_row::m_has_payment_id,
      "m_has_view_skey",  &wallet2::address_book_row::m_has_view_skey,
      "m_view_skey",      &wallet2::address_book_row::m_view_skey,
      "m_short_name",     &wallet2::address_book_row::m_short_name,
      "m_timestamp",      &wallet2::address_book_row::m_timestamp);
      //"m_short_name_color",      &wallet2::address_book_row::m_short_name_color,
      //"m_short_name_background", &wallet2::address_book_row::m_short_name_background,

    tools.new_usertype<wallet2::message_list_row>("message_list_row",
      "m_sender",         &wallet2::message_list_row::m_sender,
      "m_text",           &wallet2::message_list_row::m_text,
      "m_description",    &wallet2::message_list_row::m_description,
      "m_short_name",     &wallet2::message_list_row::m_short_name,
      "m_height",         &wallet2::message_list_row::m_height,
      "m_timestamp",      &wallet2::message_list_row::m_timestamp,
      "m_txid",           &wallet2::message_list_row::m_txid);

    if(S)
    {
      tools.new_usertype<wallet2::pending_tx>("pending_tx",
        "tx_key", &wallet2::pending_tx::tx_key,
        "tx", &wallet2::pending_tx::tx,
        "dust", sol::readonly_property([](const wallet2::pending_tx& ptx) { return U64{ ptx.dust}; }),
        "fee", sol::readonly_property([](const wallet2::pending_tx& ptx) { return U64{ ptx.fee}; })
      );

      tools.new_usertype<wallet2::transfer_details>("transfer_details",
        "height", sol::readonly_property([](wallet2::transfer_details& td) { return U64{td.m_block_height}; }),
        "txid", &wallet2::transfer_details::m_txid,
        "tx", &wallet2::transfer_details::m_tx,
        "amount", sol::readonly_property([](wallet2::transfer_details& td) { return U64{td.m_amount}; })
      );

      auto wallet2_interface_ctor = [S]() { return std::make_shared<wallet2_interface>(S); };
      auto wallet2_interface_ctor_2 = [S](sol::object)  { return std::make_shared<wallet2_interface>(S); };

      tools.new_usertype<wallet2_interface>("wallet2",
        sol::meta_function::construct,    sol::factories(wallet2_interface_ctor, wallet2_interface_ctor_2),
        sol::call_constructor,            wallet2_interface_ctor,
        "generate",                       &wallet2_interface::generate,
        "open_or_create",                 &wallet2_interface::open_or_create,
        "cryptonote_name",                &wallet2_interface::cryptonote_name,
        "coin_name",                      &wallet2_interface::coin_name,
        "millicoin_name",                 &wallet2_interface::millicoin_name,
        "microcoin_name",                 &wallet2_interface::microcoin_name,
        "nanocoin_name",                  &wallet2_interface::nanocoin_name,
        "picocoin_name",                  &wallet2_interface::picocoin_name,
        "get_wallet_name",                &wallet2_interface::get_wallet_name,
        "set_attribute",                  &wallet2_interface::set_attribute,
        "get_attribute",                  &wallet2_interface::get_attribute,
        "get_address",                    &wallet2_interface::get_address,
        "get_address_book_row",           &wallet2_interface::get_address_book_row,
        "get_address_book_count",         &wallet2_interface::get_address_book_count,
        "add_address_book_row",           &wallet2_interface::add_address_book_row,
        "set_address_book_row",           &wallet2_interface::set_address_book_row,
        "get_address_book_row_id",        &wallet2_interface::get_address_book_row_id,
        "is_address_book_row_multi_user", &wallet2_interface::is_address_book_row_multi_user,
        "do_message_chat_send",           &wallet2_interface::do_message_chat_send,
        "add_message_to_chat",            &wallet2_interface::add_message_to_chat,
        "get_message_from_chat",          &wallet2_interface::get_message_from_chat,
        "get_message_chat_size",          &wallet2_interface::get_message_chat_size,
        "get_message_chat_unread",        &wallet2_interface::get_message_chat_unread,
        "get_message_chat_timestamp",     &wallet2_interface::get_message_chat_timestamp,
        "commit_tx",                      &wallet2_interface::commit_tx,
        "get_transfers",                  &wallet2_interface::get_transfers,
        "create_transaction",             &wallet2_interface::create_transaction,
        "get_tx_proof",                   &wallet2_interface::get_tx_proof,
        "check_tx_proof",                 &wallet2_interface::check_tx_proof,
        "set_refresh_from_block_height",  &wallet2_interface::set_refresh_from_block_height,
        "get_refresh_from_block_height",  &wallet2_interface::get_refresh_from_block_height,
        "get_daemon_blockchain_height",   &wallet2_interface::get_daemon_blockchain_height,
        "refresh",                        &wallet2_interface::refresh,
        "estimate_fee",                   &wallet2_interface::estimate_fee,
        "get_base_fee",                   &wallet2_interface::get_base_fee,
        "get_fee_quantization_mask",      &wallet2_interface::get_fee_quantization_mask,
        "get_min_ring_size",              &wallet2_interface::get_min_ring_size,
        "get_max_ring_size",              &wallet2_interface::get_max_ring_size,
        "adjust_mixin",                   &wallet2_interface::adjust_mixin,
        "adjust_priority",                &wallet2_interface::adjust_priority,
        "set_ring_database",              &wallet2_interface::set_ring_database,
        "get_ring_database",              &wallet2_interface::get_ring_database,
        "balance_all",                    &wallet2_interface::balance_all,
        "unlocked_balance_all",           &wallet2_interface::unlocked_balance_all,
        sol::meta_function::new_index,    &wallet2_interface::new_index
      );

      tools["wallet"] = S->interface_;

      tools.new_usertype<cryptonote::address_parse_info>("address_parse_info",
        "address",         &cryptonote::address_parse_info::address,
        "is_subaddress",   &cryptonote::address_parse_info::is_subaddress,
        "has_payment_id",  &cryptonote::address_parse_info::has_payment_id,
        "has_view_skey",   &cryptonote::address_parse_info::has_view_skey,
        "payment_id",      &cryptonote::address_parse_info::payment_id,
        "view_skey",       &cryptonote::address_parse_info::view_skey);
      
      cryptonote["get_account_address_as_str"] = [S](const cryptonote::account_public_address& addr, sol::object is_subaddress) {
        return get_account_address_as_str(S->wallet_->nettype(), is_subaddress == sol::lua_nil ? false : is_subaddress.as<bool>(), addr);
      };
      
      cryptonote["get_account_integrated_address_as_str"] = [S](const cryptonote::account_public_address& addr, const crypto::hash8& payment_id) {
        return get_account_integrated_address_as_str(S->wallet_->nettype(), addr, payment_id);
      };
      
      cryptonote["get_account_channel_address_as_str"] = [S](const crypto::public_key& spend_pkey, const crypto::secret_key& view_skey) {
        return get_account_channel_address_as_str(S->wallet_->nettype(), spend_pkey, view_skey);
      };
      
      cryptonote["get_account_address_from_str"] = [S](const std::string& str, sol::this_state L) {
        cryptonote::address_parse_info info;
        bool ok = cryptonote::get_account_address_from_str(info, S->wallet_->nettype(), str);
        sol::variadic_results rc;
        rc.push_back({ L, sol::in_place_type<bool>, ok });
        rc.push_back({ L, sol::in_place_type<cryptonote::address_parse_info>, info });
        return rc;
      };
    }

    return true;
  }

  void simple::on_message_chat_received(
       uint64_t height,
       const crypto::hash& txid,
       uint64_t type,
       uint64_t freq,
       const cryptonote::account_public_address& chat,
       uint64_t n,
       const cryptonote::account_public_address& sender,
       const std::string& text,
       const std::string& description,
       const std::string& short_name,
       bool enable_comments,
       uint64_t timestamp,
       const crypto::hash& parent)
  {
    auto f = meth_.find("on_message_chat_received");
    if(f != meth_.end()) {
      std::lock_guard<std::mutex> lock(lua_mx_);
      sol::protected_function_result pfr = f->second(
        interface_, U64{height}, txid, type, freq, chat, U64{n}, sender, text, description, short_name, enable_comments, U64{timestamp}, parent);
      if(!pfr.valid()) {
        sol::error err = pfr;
        sol::call_status status = pfr.status();
        MLOG_RED(el::Level::Warning, "Lua wrong: " << sol::to_string(status) << ", Error: " << err.what());
      }
    }
  }

  void simple::on_message_chat_removed(const crypto::hash& txid)
  {
    auto f = meth_.find("on_message_chat_removed");
    if(f != meth_.end()) {
      std::lock_guard<std::mutex> lock(lua_mx_);
      sol::protected_function_result pfr = f->second(interface_, txid);
      if(!pfr.valid()) {
        sol::error err = pfr;
        sol::call_status status = pfr.status();
        MLOG_RED(el::Level::Warning, "Lua wrong: " << sol::to_string(status) << ", Error: " << err.what());
      }
    }
  }

  void simple::on_atomic_swap_x_received(
       const crypto::hash& txid,
       const std::string& x)
  {
    auto f = meth_.find("on_atomic_swap_x_received");
    if(f != meth_.end()) {
      std::lock_guard<std::mutex> lock(lua_mx_);
      sol::protected_function_result pfr = f->second(
        interface_, txid, x);
      if(!pfr.valid()) {
        sol::error err = pfr;
        sol::call_status status = pfr.status();
        MLOG_RED(el::Level::Warning, "Lua wrong: " << sol::to_string(status) << ", Error: " << err.what());
      }
    }
  }

  bool simple::call(const std::string& name, const std::string& pars, func_t reply)
  {
    auto f = meth_.find(name);
    if(f != meth_.end()) {
      msgpack_in mpars{pars.data(), pars.size()};
      std::lock_guard<std::mutex> lock(lua_mx_);
      sol::protected_function_result pfr = f->second(interface_, mpars);
      if(!pfr.valid()) {
        sol::error err = pfr;
        sol::call_status status = pfr.status();
        MLOG_RED(el::Level::Warning, "Lua wrong: " << sol::to_string(status) << ", Error: " << err.what());
      } else if(pfr.return_count()>0) {
        std::string buf;
        xpack(pfr.lua_state(),
          pfr.stack_index(),
          pfr.stack_index()+pfr.return_count()-1, buf);
        reply(buf);
      }
      return true;
    }
    return false;
  }

  bool simple::call(const std::string& name, const std::string& pars)
  {
    auto f = meth_.find(name);
    if(f != meth_.end()) {
      msgpack_in mpars{pars.data(), pars.size()};
      std::lock_guard<std::mutex> lock(lua_mx_);
      sol::protected_function_result pfr = f->second(interface_, mpars);
      if(!pfr.valid()) {
        sol::error err = pfr;
        sol::call_status status = pfr.status();
        MLOG_RED(el::Level::Warning, "Lua wrong: " << sol::to_string(status) << ", Error: " << err.what());
      }
      return true;
    }
    MLOG_RED(el::Level::Warning, "Lua wrong call function: " << name);
    return false;
  }

  bool simple::init()
  {
    L_.open_libraries();
    if(!reg(L_, this)) return false;

    std::string file = wallet_->get_wallet_file();
    file = epee::string_tools::cut_off_extension(file);
    file += ".lua";

    if(!boost::filesystem::exists(file))
    {
      const char *xboost_path = std::getenv("XBOOST_LUA");
      if(xboost_path)
      {
        file = std::string(xboost_path) + "/wallet.lua";
        if(!boost::filesystem::exists(file))
        {
          file = boost::filesystem::path(file).parent_path().parent_path().string() + "/wallet.lua";
          if(!boost::filesystem::exists(file))
          {
            MLOG_RED(el::Level::Warning, "file not found: " << file);
            return false;
          }
        }
      }
    }

    try
    {
      std::lock_guard<std::mutex> lock(lua_mx_);
      sol::protected_function_result pfr = L_.script_file(file);
      if(!pfr.valid())
      {
        sol::error err = pfr;
        sol::call_status status = pfr.status();
        MLOG_RED(el::Level::Warning, "Lua wrong: " << sol::to_string(status) << ", Error: " << err.what());
      }
    }
    catch (std::exception const & e)
    {
      MLOG_RED(el::Level::Warning, e.what());
      return false;
    }
    return true;
  }

  size_t simple::idle(uint64_t t)
  {
    size_t cnt = 0;
    try
    {
      cnt = zyre::idle(t);
    }
    catch (std::exception const & e)
    {
      LOG(ERROR) << e.what();
    }
    return cnt;
  }

  #define id_int64_t                1
  #define id_uint64_t               2
  #define id_hash                   3
  #define id_hash8                  4
  #define id_public_key             5
  #define id_secret_key             6
  #define id_key_derivation         7
  #define id_account_public_address 8
  //#define id_transaction            9

  #define XPACK(id, otype) \
    if(o.is<otype>()) { \
      otype v = o.as<otype>(); \
      const char *first = (const char *)&v; \
      const char *end = first + sizeof(otype); \
      out.insert(out.end(), first, end); \
      return id; \
    }

  #define XPACK_R(id, otype) \
    if(o.is<otype>()) { \
      const char *first = (const char *)&o.as<otype>(); \
      const char *end = first + sizeof(otype); \
      out.insert(out.end(), first, end); \
      return id; \
    }

  size_t xpack_userdata(lua_State *L, int index, std::string& out)
  {
    sol::stack_object o(L, index);
    XPACK(id_int64_t, I64);
    XPACK(id_uint64_t, U64);
    XPACK_R(id_hash, crypto::hash);
    XPACK_R(id_hash8, crypto::hash8);
    XPACK_R(id_public_key, crypto::public_key);
    XPACK_R(id_secret_key, crypto::secret_key);
    XPACK_R(id_key_derivation, crypto::key_derivation);
    XPACK_R(id_account_public_address, cryptonote::account_public_address);
    luaL_error(L,"Failed type userdata to msgpack");
    return -1;
  }

  #define XUNPACK(id, otype) \
    case id: \
      if(sz == sizeof(otype)) \
      { \
        otype a; \
        memcpy(&a, p, sizeof(otype)); \
        sol::stack::push(L, a); \
        return; \
      }

  void xunpack_userdata(lua_State *L, int64_t a)
  {
    sol::stack::push(L, I64{a});
  }

  void xunpack_userdata(lua_State *L, uint64_t a)
  {
    sol::stack::push(L, U64{a});
  }

  void xunpack_userdata(lua_State *L, size_t t, char *p, size_t sz)
  {
    switch(t)
    {
      XUNPACK(id_int64_t, I64);
      XUNPACK(id_uint64_t, U64);
      XUNPACK(id_hash, crypto::hash);
      XUNPACK(id_hash8, crypto::hash8);
      XUNPACK(id_public_key, crypto::public_key);
      XUNPACK(id_secret_key, crypto::secret_key);
      XUNPACK(id_key_derivation, crypto::key_derivation);
      XUNPACK(id_account_public_address, cryptonote::account_public_address);
    }
    luaL_error(L,"Failed type userdata to msgpack");
  }

}}
