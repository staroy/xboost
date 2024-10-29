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

#include "common/command_line.h"
#include "common/scoped_message_writer.h"
#include "common/password.h"
#include "common/util.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_basic/miner.h"
#include "daemon/command_server.h"
#include "daemon/daemon.h"
#include "daemon/executor.h"
#include "daemonizer/daemonizer.h"
#include "misc_log_ex.h"
#include "net/parse.h"
#include "p2p/net_node.h"
#include "rpc/core_rpc_server.h"
#include "rpc/rpc_args.h"
#include "daemon/command_line_args.h"
#include "version.h"

#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_io.hpp>

#ifdef STACK_TRACE
#include "common/stack_trace.h"
#endif // STACK_TRACE

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon"

namespace po = boost::program_options;
namespace bf = boost::filesystem;

void generate_genesis_tx(const std::string& filepath)
{
  config::new_network_id();

  cryptonote::transaction tx;
  cryptonote::blobdata extra;
  std::vector<cryptonote::data_tx_proof> proofs;

  cryptonote::account_base acc;
  acc.generate();

  cryptonote::keypair key = cryptonote::keypair::generate(hw::get_device("default"));
  crypto::secret_key mine_key = key.sec;

  crypto::hash hash;
  crypto::cn_fast_hash(key.pub.data, sizeof(crypto::public_key), hash);

  const cryptonote::account_keys &keys = acc.get_keys();

  crypto::signature mine_sig;
  crypto::generate_signature(hash, keys.m_account_address.m_spend_public_key, keys.m_spend_secret_key, mine_sig);

  cryptonote::construct_miner_tx_0(cryptonote::MAINNET, 0, 0, 0, 0, acc.get_keys().m_account_address, proofs, mine_key, mine_sig, tx, extra);

  size_t size = cryptonote::get_object_blobsize(tx);
  cryptonote::construct_miner_tx_0(cryptonote::MAINNET, 0, 0, size, 0, acc.get_keys().m_account_address, proofs, mine_key, mine_sig, tx, extra);

  std::ofstream of(filepath, std::ofstream::out);
  of << "CRYPTONOTE_NAME=" << CRYPTONOTE_NAME << "\n";
  of << "COIN_NAME=" << COIN_NAME << "\n";
  of << "MILLICOIN_NAME=" << MILLICOIN_NAME << "\n";
  of << "MICROCOIN_NAME=" << MICROCOIN_NAME << "\n";
  of << "NANOCOIN_NAME=" << NANOCOIN_NAME << "\n";
  of << "PICOCOIN_NAME=" << PICOCOIN_NAME << "\n";
  of << "CRYPTONOTE_DISPLAY_DECIMAL_POINT=" << CRYPTONOTE_DISPLAY_DECIMAL_POINT << "\n";
  of << "COIN=" << COIN << "\n";
  of << "EMISSION_SPEED_FACTOR_PER_MINUTE=" << EMISSION_SPEED_FACTOR_PER_MINUTE << "\n";
  of << "FINAL_SUBSIDY_PER_MINUTE=" << FINAL_SUBSIDY_PER_MINUTE << "\n";
  of << "DIFFICULTY_TARGET_V2=" << DIFFICULTY_TARGET_V2 << "\n";
  of << "DIFFICULTY_TARGET_V1=" << DIFFICULTY_TARGET_V1 << "\n";
  of << "MAX_TX_EXTRA_SIZE=" << MAX_TX_EXTRA_SIZE << "\n";
  of << "MAX_TX_EXTRA_MSG_SIZE=" << MAX_TX_EXTRA_MSG_SIZE << "\n";
  of << "MAX_TX_MSG_PRUNABLE_SIZE=" << MAX_TX_MSG_PRUNABLE_SIZE << "\n";
  of << "CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW=" << CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_DEFAULT << "\n";
  of << "CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE=" << CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE_DEFAULT << "\n";
  of << "BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW=" << BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_DEFAULT << "\n";
  of << "CRYPTONOTE_PRUNING_TIP_BLOCKS=" << CRYPTONOTE_PRUNING_TIP_BLOCKS << "\n";
  of << "CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX=" << config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX << "\n";
  of << "CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX=" << config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX << "\n";
  of << "CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX=" << config::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX << "\n";
  of << "CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX=" << config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX << "\n";
  of << "P2P_DEFAULT_PORT=" << config::P2P_DEFAULT_PORT << "\n";
  of << "RPC_DEFAULT_PORT=" << config::RPC_DEFAULT_PORT << "\n";
  of << "ZMQ_RPC_DEFAULT_PORT=" << config::ZMQ_RPC_DEFAULT_PORT << "\n";
  of << "GENESIS_NONCE=" << config::GENESIS_NONCE << "\n";
  of << "GENESIS_TIMESTAMP=" << config::GENESIS_TIMESTAMP << "\n";
  of << "GENESIS_TX=" << epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(tx)) << "\n";
  of << "NETWORK_ID=" << boost::lexical_cast<std::string>(config::NETWORK_ID) << "\n";
  of.close();

  cryptonote::tx_extra_chain_id chain_id;
  cryptonote::get_chain_id_from_extra(tx.extra, chain_id);
  MGINFO("main chain_id='" << epee::string_tools::pod_to_hex(chain_id.id) << "'\n");
}

void generate_genesis_tx_testnet(const std::string& filepath)
{
  config::new_testnet_network_id();

  cryptonote::transaction tx;
  cryptonote::blobdata extra;
  std::vector<cryptonote::data_tx_proof> proofs;

  cryptonote::account_base acc;
  acc.generate();

  cryptonote::keypair key = cryptonote::keypair::generate(hw::get_device("default"));
  crypto::secret_key mine_key = key.sec;

  crypto::hash hash;
  crypto::cn_fast_hash(key.pub.data, sizeof(crypto::public_key), hash);

  const cryptonote::account_keys &keys = acc.get_keys();

  crypto::signature mine_sig;
  crypto::generate_signature(hash, keys.m_account_address.m_spend_public_key, keys.m_spend_secret_key, mine_sig);

  cryptonote::construct_miner_tx_0(cryptonote::TESTNET, 0, 0, 0, 0, acc.get_keys().m_account_address, proofs, mine_key, mine_sig, tx, extra);

  size_t size = cryptonote::get_object_blobsize(tx);
  cryptonote::construct_miner_tx_0(cryptonote::TESTNET, 0, 0, size, 0, acc.get_keys().m_account_address, proofs, mine_key, mine_sig, tx, extra);

  std::ofstream of(filepath, std::ofstream::app);
  of << "[testnet]\n";
  of << "CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX=" << config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX << "\n";
  of << "CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX=" << config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX << "\n";
  of << "CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX=" << config::testnet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX << "\n";
  of << "CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX=" << config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX << "\n";
  of << "P2P_DEFAULT_PORT=" << config::testnet::P2P_DEFAULT_PORT << "\n";
  of << "RPC_DEFAULT_PORT=" << config::testnet::RPC_DEFAULT_PORT << "\n";
  of << "ZMQ_RPC_DEFAULT_PORT=" << config::testnet::ZMQ_RPC_DEFAULT_PORT << "\n";
  of << "GENESIS_NONCE=" << config::testnet::GENESIS_NONCE << "\n";
  of << "GENESIS_TIMESTAMP=" << config::testnet::GENESIS_TIMESTAMP << "\n";
  of << "GENESIS_TX=" << epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(tx)) << "\n";
  of << "NETWORK_ID=" << boost::lexical_cast<std::string>(config::testnet::NETWORK_ID) << "\n";
  of.close();

  cryptonote::tx_extra_chain_id chain_id;
  cryptonote::get_chain_id_from_extra(tx.extra, chain_id);
  MGINFO("test chain_id='" << epee::string_tools::pod_to_hex(chain_id.id) << "'\n");
}

void generate_genesis_tx_stagenet(const std::string& filepath)
{
  config::new_stagenet_network_id();

  cryptonote::transaction tx;
  cryptonote::blobdata extra;
  std::vector<cryptonote::data_tx_proof> proofs;

  cryptonote::account_base acc;
  acc.generate();

  cryptonote::keypair key = cryptonote::keypair::generate(hw::get_device("default"));
  crypto::secret_key mine_key = key.sec;

  crypto::hash hash;
  crypto::cn_fast_hash(key.pub.data, sizeof(crypto::public_key), hash);

  const cryptonote::account_keys &keys = acc.get_keys();

  crypto::signature mine_sig;
  crypto::generate_signature(hash, keys.m_account_address.m_spend_public_key, keys.m_spend_secret_key, mine_sig);

  cryptonote::construct_miner_tx_0(cryptonote::STAGENET, 0, 0, 0, 0, acc.get_keys().m_account_address, proofs, mine_key, mine_sig, tx, extra);

  size_t size = cryptonote::get_object_blobsize(tx);
  cryptonote::construct_miner_tx_0(cryptonote::STAGENET, 0, 0, size, 0, acc.get_keys().m_account_address, proofs, mine_key, mine_sig, tx, extra);

  std::ofstream of(filepath, std::ofstream::app);
  of << "[stagenet]\n";
  of << "CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX=" << config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX << "\n";
  of << "CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX=" << config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX << "\n";
  of << "CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX=" << config::stagenet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX << "\n";
  of << "CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX=" << config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX << "\n";
  of << "P2P_DEFAULT_PORT=" << config::stagenet::P2P_DEFAULT_PORT << "\n";
  of << "RPC_DEFAULT_PORT=" << config::stagenet::RPC_DEFAULT_PORT << "\n";
  of << "ZMQ_RPC_DEFAULT_PORT=" << config::stagenet::ZMQ_RPC_DEFAULT_PORT << "\n";
  of << "GENESIS_NONCE=" << config::stagenet::GENESIS_NONCE << "\n";
  of << "GENESIS_TIMESTAMP=" << config::stagenet::GENESIS_TIMESTAMP << "\n";
  of << "GENESIS_TX=" << epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(tx)) << "\n";
  of << "NETWORK_ID=" << boost::lexical_cast<std::string>(config::stagenet::NETWORK_ID) << "\n";
  of.close();

  cryptonote::tx_extra_chain_id chain_id;
  cryptonote::get_chain_id_from_extra(tx.extra, chain_id);
  MGINFO("stage chain_id='" << epee::string_tools::pod_to_hex(chain_id.id) << "'\n");
}

uint16_t parse_public_rpc_port(const po::variables_map &vm)
{
  const auto &public_node_arg = daemon_args::arg_public_node;
  const bool public_node = command_line::get_arg(vm, public_node_arg);
  if (!public_node)
  {
    return 0;
  }

  std::string rpc_port_str;
  std::string rpc_bind_address = command_line::get_arg(vm, cryptonote::rpc_args::descriptors().rpc_bind_ip);
  const auto &restricted_rpc_port = cryptonote::core_rpc_server::arg_rpc_restricted_bind_port;
  if (!command_line::is_arg_defaulted(vm, restricted_rpc_port))
  {
    rpc_port_str = command_line::get_arg(vm, restricted_rpc_port);
    rpc_bind_address = command_line::get_arg(vm, cryptonote::rpc_args::descriptors().rpc_restricted_bind_ip);
  }
  else if (command_line::get_arg(vm, cryptonote::core_rpc_server::arg_restricted_rpc))
  {
    rpc_port_str = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);
  }
  else
  {
    throw std::runtime_error("restricted RPC mode is required");
  }

  uint16_t rpc_port;
  if (!string_tools::get_xtype_from_string(rpc_port, rpc_port_str))
  {
    throw std::runtime_error("invalid RPC port " + rpc_port_str);
  }

  const auto address = net::get_network_address(rpc_bind_address, rpc_port);
  if (!address) {
    throw std::runtime_error("failed to parse RPC bind address");
  }
  if (address->get_zone() != epee::net_utils::zone::public_)
  {
    throw std::runtime_error(std::string(zone_to_string(address->get_zone()))
      + " network zone is not supported, please check RPC server bind address");
  }

  if (address->is_loopback() || address->is_local())
  {
    MLOG_RED(el::Level::Warning, "--" << public_node_arg.name 
      << " is enabled, but RPC server " << address->str() 
      << " may be unreachable from outside, please check RPC server bind address");
  }

  return rpc_port;
}

#ifdef WIN32
bool isFat32(const wchar_t* root_path)
{
  std::vector<wchar_t> fs(MAX_PATH + 1);
  if (!::GetVolumeInformationW(root_path, nullptr, 0, nullptr, 0, nullptr, &fs[0], MAX_PATH))
  {
    MERROR("Failed to get '" << root_path << "' filesystem name. Error code: " << ::GetLastError());
    return false;
  }

  return wcscmp(L"FAT32", &fs[0]) == 0;
}
#endif

int main(int argc, char const * argv[])
{
  try {

    // TODO parse the debug options like set log level right here at start

    tools::on_startup();

    epee::string_tools::set_module_name_and_folder(argv[0]);

    // Build argument description
    po::options_description all_options("All");
    po::options_description hidden_options("Hidden");
    po::options_description visible_options("Options");
    po::options_description core_settings("Settings");
    po::positional_options_description positional_options;
    {
      // Misc Options

      command_line::add_arg(visible_options, command_line::arg_help);
      command_line::add_arg(visible_options, command_line::arg_version);
      command_line::add_arg(visible_options, daemon_args::arg_os_version);
      command_line::add_arg(visible_options, daemon_args::arg_config_file);

      // Settings
      command_line::add_arg(core_settings, daemon_args::arg_log_file);
      command_line::add_arg(core_settings, daemon_args::arg_log_level);
      command_line::add_arg(core_settings, daemon_args::arg_max_log_file_size);
      command_line::add_arg(core_settings, daemon_args::arg_max_log_files);
      command_line::add_arg(core_settings, daemon_args::arg_max_concurrency);
      command_line::add_arg(core_settings, daemon_args::arg_proxy);
      command_line::add_arg(core_settings, daemon_args::arg_proxy_allow_dns_leaks);
      command_line::add_arg(core_settings, daemon_args::arg_public_node);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_rpc_bind_ip);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_rpc_bind_port);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_pub);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_rpc_disabled);
      command_line::add_arg(core_settings, daemon_args::arg_genesis_tx);

      config::init_options(core_settings);
      daemonizer::init_options(hidden_options, visible_options);
      daemonize::t_executor::init_options(core_settings);

      // Hidden options
      command_line::add_arg(hidden_options, daemon_args::arg_command);

      visible_options.add(core_settings);
      all_options.add(visible_options);
      all_options.add(hidden_options);

      // Positional
      positional_options.add(daemon_args::arg_command.name, -1); // -1 for unlimited arguments
    }

    // Do command line parsing
    po::variables_map vm;
    bool ok = command_line::handle_error_helper(visible_options, [&]()
    {
      boost::program_options::store(
        boost::program_options::command_line_parser(argc, argv)
          .options(all_options).positional(positional_options).run()
      , vm
      );

      return true;
    });
    if (!ok) return 1;

    if (command_line::get_arg(vm, command_line::arg_help))
    {
      std::cout << "Lid '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
      std::cout << "Usage: " + std::string{argv[0]} + " [options|settings] [daemon_command...]" << std::endl << std::endl;
      std::cout << visible_options << std::endl;
      return 0;
    }

    // Monero Version
    if (command_line::get_arg(vm, command_line::arg_version))
    {
      std::cout << "Lid '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL;
      return 0;
    }

    // OS
    if (command_line::get_arg(vm, daemon_args::arg_os_version))
    {
      std::cout << "OS: " << tools::get_os_version_string() << ENDL;
      return 0;
    }

    std::string config = command_line::get_arg(vm, daemon_args::arg_config_file);
    boost::filesystem::path config_path(config);
    boost::system::error_code ec;
    if (bf::exists(config_path, ec))
    {
      try
      {
        po::store(po::parse_config_file<char>(config_path.string<std::string>().c_str(), core_settings), vm);
      }
      catch (const po::unknown_option &e)
      {
        std::string unrecognized_option = e.get_option_name();
        if (all_options.find_nothrow(unrecognized_option, false))
        {
          std::cerr << "Option '" << unrecognized_option << "' is not allowed in the config file, please use it as a command line flag." << std::endl;
        }
        else
        {
          std::cerr << "Unrecognized option '" << unrecognized_option << "' in config file." << std::endl;
        }
        return 1;
      }
      catch (const std::exception &e)
      {
        // log system isn't initialized yet
        std::cerr << "Error parsing config file: " << e.what() << std::endl;
        throw;
      }
    }
    else if (!command_line::is_arg_defaulted(vm, daemon_args::arg_config_file))
    {
      std::cerr << "Can't find config file " << config << std::endl;
      return 1;
    }

    // config
    ::config::init(vm);

    const bool testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
    const bool stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
    const bool regtest = command_line::get_arg(vm, cryptonote::arg_regtest_on);
    if (testnet + stagenet + regtest > 1)
    {
      std::cerr << "Can't specify more than one of --tesnet and --stagenet and --regtest" << ENDL;
      return 1;
    }

    std::string genesis_tx_filepath = command_line::get_arg(vm, daemon_args::arg_genesis_tx);
    if (!genesis_tx_filepath.empty())
    {
      if(!testnet && !stagenet)
        generate_genesis_tx(genesis_tx_filepath);
      else if(testnet)
        generate_genesis_tx_testnet(genesis_tx_filepath);
      else if(stagenet)
        generate_genesis_tx_stagenet(genesis_tx_filepath);
      return 0;
    }

    // data_dir
    //   default: e.g. ~/.bitmonero/ or ~/.bitmonero/testnet
    //   if data-dir argument given:
    //     absolute path
    //     relative path: relative to cwd

    // Create data dir if it doesn't exist
    boost::filesystem::path data_dir = boost::filesystem::absolute(
        command_line::get_arg(vm, cryptonote::arg_data_dir));

#ifdef WIN32
    if (isFat32(data_dir.root_path().c_str()))
    {
      MERROR("Data directory resides on FAT32 volume that has 4GiB file size limit, blockchain might get corrupted.");
    }
#endif

    // FIXME: not sure on windows implementation default, needs further review
    //bf::path relative_path_base = daemonizer::get_relative_path_base(vm);
    bf::path relative_path_base = data_dir;

    po::notify(vm);

    // log_file_path
    //   default: <data_dir>/<CRYPTONOTE_NAME>.log
    //   if log-file argument given:
    //     absolute path
    //     relative path: relative to data_dir
    bf::path log_file_path {data_dir / (CRYPTONOTE_NAME + ".log")};
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_file))
      log_file_path = command_line::get_arg(vm, daemon_args::arg_log_file);
    if (!log_file_path.has_parent_path())
      log_file_path = bf::absolute(log_file_path, relative_path_base);
    mlog_configure(log_file_path.string(), true, command_line::get_arg(vm, daemon_args::arg_max_log_file_size), command_line::get_arg(vm, daemon_args::arg_max_log_files));

    // Set log level
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_level))
    {
      mlog_set_log(command_line::get_arg(vm, daemon_args::arg_log_level).c_str());
    }

    // after logs initialized
    tools::create_directories_if_necessary(data_dir.string());

#ifdef STACK_TRACE
    tools::set_stack_trace_log(log_file_path.filename().string());
#endif // STACK_TRACE

    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_max_concurrency))
      tools::set_max_concurrency(command_line::get_arg(vm, daemon_args::arg_max_concurrency));

    // logging is now set up
    MGINFO("Lid '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")");

    // If there are positional options, we're running a daemon command
    {
      auto command = command_line::get_arg(vm, daemon_args::arg_command);

      if (command.size())
      {
        const cryptonote::rpc_args::descriptors arg{};
        auto rpc_ip_str = command_line::get_arg(vm, arg.rpc_bind_ip);
        auto rpc_port_str = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);

        uint32_t rpc_ip;
        uint16_t rpc_port;
        if (!epee::string_tools::get_ip_int32_from_string(rpc_ip, rpc_ip_str))
        {
          std::cerr << "Invalid IP: " << rpc_ip_str << std::endl;
          return 1;
        }
        if (!epee::string_tools::get_xtype_from_string(rpc_port, rpc_port_str))
        {
          std::cerr << "Invalid port: " << rpc_port_str << std::endl;
          return 1;
        }

        const char *env_rpc_login = nullptr;
        const bool has_rpc_arg = command_line::has_arg(vm, arg.rpc_login);
        const bool use_rpc_env = !has_rpc_arg && (env_rpc_login = getenv("RPC_LOGIN")) != nullptr && strlen(env_rpc_login) > 0;
        boost::optional<tools::login> login{};
        if (has_rpc_arg || use_rpc_env)
        {
          login = tools::login::parse(
            has_rpc_arg ? command_line::get_arg(vm, arg.rpc_login) : std::string(env_rpc_login), false, [](bool verify) {
              PAUSE_READLINE();
              return tools::password_container::prompt(verify, "Daemon client password");
            }
          );
          if (!login)
          {
            std::cerr << "Failed to obtain password" << std::endl;
            return 1;
          }
        }

        auto ssl_options = cryptonote::rpc_args::process_ssl(vm, true);
        if (!ssl_options)
          return 1;

        daemonize::t_command_server rpc_commands{rpc_ip, rpc_port, std::move(login), std::move(*ssl_options)};
        if (rpc_commands.process_command_vec(command))
        {
          return 0;
        }
        else
        {
          PAUSE_READLINE();
          std::cerr << "Unknown command: " << command.front() << std::endl;
          return 1;
        }
      }
    }

    MINFO("Moving from main() into the daemonize now.");

    return daemonizer::daemonize(argc, argv, daemonize::t_executor{parse_public_rpc_port(vm)}, vm) ? 0 : 1;
  }
  catch (std::exception const & ex)
  {
    LOG_ERROR("Exception in main! " << ex.what());
  }
  catch (...)
  {
    LOG_ERROR("Exception in main!");
  }
  return 1;
}
