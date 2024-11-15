#include <stdexcept>

#include "cryptonote_config.h"
#include "common/command_line.h"
#include "string_tools.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"

#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/string_generator.hpp>
#include <boost/filesystem.hpp>

#ifdef CRYPTONOTE_CONFIGURABLE

uint64_t EMISSION_SPEED_FACTOR_PER_MINUTE = EMISSION_SPEED_FACTOR_PER_MINUTE_DEFAULT;
uint64_t FINAL_SUBSIDY_PER_MINUTE = FINAL_SUBSIDY_PER_MINUTE_DEFAULT;

uint32_t CRYPTONOTE_DISPLAY_DECIMAL_POINT = CRYPTONOTE_DISPLAY_DECIMAL_POINT_DEFAULT; // COIN - number of smallest units in one coin
uint64_t COIN = COIN_DEFAULT; //(uint64_t)1000000000000; // pow(10, 12)

std::string CRYPTONOTE_NAME    = CRYPTONOTE_NAME_DEFAULT;
std::string COIN_NAME          = COIN_NAME_DEFAULT;
std::string MILLICOIN_NAME     = MILLICOIN_NAME_DEFAULT;
std::string MICROCOIN_NAME     = MICROCOIN_NAME_DEFAULT;
std::string NANOCOIN_NAME      = NANOCOIN_NAME_DEFAULT;
std::string PICOCOIN_NAME      = PICOCOIN_NAME_DEFAULT;
			       
uint64_t DIFFICULTY_TARGET_V2  = DIFFICULTY_TARGET_V2_DEFAULT; // seconds
uint64_t DIFFICULTY_TARGET_V1  = DIFFICULTY_TARGET_V1_DEFAULT;  // seconds - before first fork

uint64_t MAX_TX_EXTRA_SIZE     = MAX_TX_EXTRA_SIZE_DEFAULT;
uint64_t MAX_TX_EXTRA_MSG_SIZE = MAX_TX_EXTRA_MSG_SIZE_DEFAULT;
uint64_t MAX_TX_MSG_PRUNABLE_SIZE = MAX_TX_MSG_PRUNABLE_SIZE_DEFAULT;
uint64_t MSG_TX_AMOUNT         = MSG_TX_AMOUNT_DEFAULT;
uint64_t FEE_PER_KB_MESSAGE_MULTIPLIER = FEE_PER_KB_MESSAGE_MULTIPLIER_DEFAULT;

uint64_t BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_DEFAULT;
uint64_t CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW = CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_DEFAULT;
uint64_t CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE_DEFAULT;
uint64_t CRYPTONOTE_PRUNING_TIP_BLOCKS = CRYPTONOTE_PRUNING_TIP_BLOCKS_DEFAULT;

// New constants are intended to go here
namespace config
{
  uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX_DEFAULT;
  uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX_DEFAULT;
  uint64_t CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX_DEFAULT;
  uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX_DEFAULT;
  uint16_t P2P_DEFAULT_PORT = P2P_DEFAULT_PORT_DEFAULT;
  uint16_t RPC_DEFAULT_PORT = RPC_DEFAULT_PORT_DEFAULT;
  uint16_t ZMQ_RPC_DEFAULT_PORT = ZMQ_RPC_DEFAULT_PORT_DEFAULT;
  boost::uuids::uuid NETWORK_ID = NETWORK_ID_DEFAULT;
  std::string GENESIS_TX = GENESIS_TX_DEFAULT;
  uint32_t GENESIS_NONCE = GENESIS_NONCE_DEFAULT;
  uint64_t GENESIS_TIMESTAMP = GENESIS_TIMESTAMP_DEFAULT;

  namespace testnet
  {
    uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX_DEFAULT;
    uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX_DEFAULT;
    uint64_t CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX_DEFAULT;
    uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX_DEFAULT;
    uint16_t P2P_DEFAULT_PORT = P2P_DEFAULT_PORT_DEFAULT;
    uint16_t RPC_DEFAULT_PORT = RPC_DEFAULT_PORT_DEFAULT;
    uint16_t ZMQ_RPC_DEFAULT_PORT = ZMQ_RPC_DEFAULT_PORT_DEFAULT;
    boost::uuids::uuid NETWORK_ID = NETWORK_ID_DEFAULT;
    std::string GENESIS_TX = GENESIS_TX_DEFAULT;
    uint32_t GENESIS_NONCE = GENESIS_NONCE_DEFAULT;
    uint64_t GENESIS_TIMESTAMP = GENESIS_TIMESTAMP_DEFAULT;
  }

  namespace stagenet
  {
    uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX_DEFAULT;
    uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX_DEFAULT;
    uint64_t CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX_DEFAULT;
    uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX_DEFAULT;
    uint16_t P2P_DEFAULT_PORT = P2P_DEFAULT_PORT_DEFAULT;
    uint16_t RPC_DEFAULT_PORT = RPC_DEFAULT_PORT_DEFAULT;
    uint16_t ZMQ_RPC_DEFAULT_PORT = ZMQ_RPC_DEFAULT_PORT_DEFAULT;
    boost::uuids::uuid NETWORK_ID = NETWORK_ID_DEFAULT;
    std::string GENESIS_TX = GENESIS_TX_DEFAULT;
    uint32_t GENESIS_NONCE = GENESIS_NONCE_DEFAULT;
    uint64_t GENESIS_TIMESTAMP = GENESIS_TIMESTAMP_DEFAULT;
  }

  const command_line::arg_descriptor<std::string> arg_CRYPTONOTE_NAME = {
    "CRYPTONOTE_NAME", "cryptonote name of coin", CRYPTONOTE_NAME_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_COIN_NAME = {
    "COIN_NAME", "name of coin", COIN_NAME_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_MILLICOIN_NAME = {
    "MILLICOIN_NAME", "milli name of coin", MILLICOIN_NAME_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_MICROCOIN_NAME = {
    "MICROCOIN_NAME", "micro name of coin", MICROCOIN_NAME_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_NANOCOIN_NAME = {
    "NANOCOIN_NAME", "nano name of coin", NANOCOIN_NAME_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_PICOCOIN_NAME = {
    "PICOCOIN_NAME", "pico name of coin", PICOCOIN_NAME_DEFAULT };
  const command_line::arg_descriptor<uint32_t> arg_CRYPTONOTE_DISPLAY_DECIMAL_POINT = {
    "CRYPTONOTE_DISPLAY_DECIMAL_POINT", "Cryptonote display decimal point", CRYPTONOTE_DISPLAY_DECIMAL_POINT_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_EMISSION_SPEED_FACTOR_PER_MINUTE = {
    "EMISSION_SPEED_FACTOR_PER_MINUTE", "emission speed factor per minute", EMISSION_SPEED_FACTOR_PER_MINUTE_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_FINAL_SUBSIDY_PER_MINUTE = {
    "FINAL_SUBSIDY_PER_MINUTE", "final subsidy per minute", FINAL_SUBSIDY_PER_MINUTE_DEFAULT }; // 3 * pow(10, 11)
  const command_line::arg_descriptor<uint64_t> arg_COIN = {
    "COIN", "COIN - number of smallest units in one coin", COIN_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_MSG_TX_AMOUNT = {
    "MSG_TX_AMOUNT", "MSG_TX_AMOUNT - number of smallest units in one coin", MSG_TX_AMOUNT_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_FEE_PER_KB_MESSAGE_MULTIPLIER = {
    "FEE_PER_KB_MESSAGE_MULTIPLIER", "FEE_PER_KB_MESSAGE_MULTIPLIER - message fee per kb multiplier", FEE_PER_KB_MESSAGE_MULTIPLIER_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_DIFFICULTY_TARGET_V2 = {
    "DIFFICULTY_TARGET_V2", "120 seconds per block", DIFFICULTY_TARGET_V2_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_DIFFICULTY_TARGET_V1 = {
    "DIFFICULTY_TARGET_V1", "60 seconds per block - before first fork", DIFFICULTY_TARGET_V1_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_MAX_TX_EXTRA_SIZE = {
    "MAX_TX_EXTRA_SIZE", "max tx extra size", MAX_TX_EXTRA_SIZE_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_MAX_TX_EXTRA_MSG_SIZE = {
    "MAX_TX_EXTRA_MSG_SIZE", "max tx extra msg size", MAX_TX_EXTRA_MSG_SIZE_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_MAX_TX_MSG_PRUNABLE_SIZE = {
    "MAX_TX_MSG_PRUNABLE_SIZE", "max tx prunable msg size", MAX_TX_MSG_PRUNABLE_SIZE_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW = {
    "CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW", "", CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = {
    "CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE", "", CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW = {
    "BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW", "", BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PRUNING_TIP_BLOCKS = {
    "CRYPTONOTE_PRUNING_TIP_BLOCKS", "", CRYPTONOTE_PRUNING_TIP_BLOCKS };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = {
    "CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX = {
    "CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = {
    "CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = {
    "CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint16_t> arg_P2P_DEFAULT_PORT = {
    "P2P_DEFAULT_PORT", "", P2P_DEFAULT_PORT_DEFAULT };
  const command_line::arg_descriptor<uint16_t> arg_RPC_DEFAULT_PORT = {
    "RPC_DEFAULT_PORT", "", RPC_DEFAULT_PORT_DEFAULT };
  const command_line::arg_descriptor<uint16_t> arg_ZMQ_RPC_DEFAULT_PORT = {
    "ZMQ_RPC_DEFAULT_PORT", "", ZMQ_RPC_DEFAULT_PORT_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_NETWORK_ID = {
    "NETWORK_ID", "", sz_NETWORK_ID_0_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_GENESIS_TX = {
    "GENESIS_TX", "", GENESIS_TX_DEFAULT };
  const command_line::arg_descriptor<uint32_t> arg_GENESIS_NONCE = {
    "GENESIS_NONCE", "", GENESIS_NONCE_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_GENESIS_TIMESTAMP = {
    "GENESIS_TIMESTAMP", "", GENESIS_TIMESTAMP_DEFAULT };


  // testnet
  namespace testnet
  {
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = {
    "testnet.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX = {
    "testnet.CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = {
    "testnet.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = {
    "testnet.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint16_t> arg_P2P_DEFAULT_PORT = {
    "testnet.P2P_DEFAULT_PORT", "", P2P_DEFAULT_PORT_DEFAULT };
  const command_line::arg_descriptor<uint16_t> arg_RPC_DEFAULT_PORT = {
    "testnet.RPC_DEFAULT_PORT", "", RPC_DEFAULT_PORT_DEFAULT };
  const command_line::arg_descriptor<uint16_t> arg_ZMQ_RPC_DEFAULT_PORT = {
    "testnet.ZMQ_RPC_DEFAULT_PORT", "", ZMQ_RPC_DEFAULT_PORT_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_NETWORK_ID = {
    "testnet.NETWORK_ID", "", sz_NETWORK_ID_1_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_GENESIS_TX = {
    "testnet.GENESIS_TX", "", GENESIS_TX_DEFAULT };
  const command_line::arg_descriptor<uint32_t> arg_GENESIS_NONCE = {
    "testnet.GENESIS_NONCE", "", GENESIS_NONCE_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_GENESIS_TIMESTAMP = {
    "testnet.GENESIS_TIMESTAMP", "", GENESIS_TIMESTAMP_DEFAULT };
  }

  // stagenet
  namespace stagenet
  {
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = {
    "stagenet.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX = {
    "stagenet.CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = {
    "stagenet.CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = {
    "stagenet.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX", "", CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX_DEFAULT };
  const command_line::arg_descriptor<uint16_t> arg_P2P_DEFAULT_PORT = {
    "stagenet.P2P_DEFAULT_PORT", "", P2P_DEFAULT_PORT_DEFAULT };
  const command_line::arg_descriptor<uint16_t> arg_RPC_DEFAULT_PORT = {
    "stagenet.RPC_DEFAULT_PORT", "", RPC_DEFAULT_PORT_DEFAULT };
  const command_line::arg_descriptor<uint16_t> arg_ZMQ_RPC_DEFAULT_PORT = {
    "stagenet.ZMQ_RPC_DEFAULT_PORT", "", ZMQ_RPC_DEFAULT_PORT_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_NETWORK_ID = {
    "stagenet.NETWORK_ID", "", sz_NETWORK_ID_2_DEFAULT };
  const command_line::arg_descriptor<std::string> arg_GENESIS_TX = {
    "stagenet.GENESIS_TX", "", GENESIS_TX_DEFAULT };
  const command_line::arg_descriptor<uint32_t> arg_GENESIS_NONCE = {
    "stagenet.GENESIS_NONCE", "", GENESIS_NONCE_DEFAULT };
  const command_line::arg_descriptor<uint64_t> arg_GENESIS_TIMESTAMP = {
    "stagenet.GENESIS_TIMESTAMP", "", GENESIS_TIMESTAMP_DEFAULT };
  }

  void init_options(boost::program_options::options_description & option_spec)
  {
      command_line::add_arg(option_spec, arg_CRYPTONOTE_NAME);
      command_line::add_arg(option_spec, arg_COIN_NAME);
      command_line::add_arg(option_spec, arg_MILLICOIN_NAME);
      command_line::add_arg(option_spec, arg_MICROCOIN_NAME);
      command_line::add_arg(option_spec, arg_NANOCOIN_NAME);
      command_line::add_arg(option_spec, arg_PICOCOIN_NAME);
      command_line::add_arg(option_spec, arg_CRYPTONOTE_DISPLAY_DECIMAL_POINT);
      command_line::add_arg(option_spec, arg_EMISSION_SPEED_FACTOR_PER_MINUTE);
      command_line::add_arg(option_spec, arg_FINAL_SUBSIDY_PER_MINUTE);
      command_line::add_arg(option_spec, arg_COIN);
      command_line::add_arg(option_spec, arg_DIFFICULTY_TARGET_V2);
      command_line::add_arg(option_spec, arg_DIFFICULTY_TARGET_V1);
      command_line::add_arg(option_spec, arg_MAX_TX_EXTRA_SIZE);
      command_line::add_arg(option_spec, arg_MAX_TX_EXTRA_MSG_SIZE);
      command_line::add_arg(option_spec, arg_MAX_TX_MSG_PRUNABLE_SIZE);
      command_line::add_arg(option_spec, arg_MSG_TX_AMOUNT);
      command_line::add_arg(option_spec, arg_FEE_PER_KB_MESSAGE_MULTIPLIER);
      command_line::add_arg(option_spec, arg_CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
      command_line::add_arg(option_spec, arg_CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
      command_line::add_arg(option_spec, arg_BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW);
      command_line::add_arg(option_spec, arg_CRYPTONOTE_PRUNING_TIP_BLOCKS);

      // main
      command_line::add_arg(option_spec, arg_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, arg_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, arg_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, arg_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, arg_P2P_DEFAULT_PORT);
      command_line::add_arg(option_spec, arg_RPC_DEFAULT_PORT);
      command_line::add_arg(option_spec, arg_ZMQ_RPC_DEFAULT_PORT);
      command_line::add_arg(option_spec, arg_NETWORK_ID);
      command_line::add_arg(option_spec, arg_GENESIS_TX);
      command_line::add_arg(option_spec, arg_GENESIS_NONCE);
      command_line::add_arg(option_spec, arg_GENESIS_TIMESTAMP);

      // testnet
      command_line::add_arg(option_spec, testnet::arg_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, testnet::arg_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, testnet::arg_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, testnet::arg_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, testnet::arg_P2P_DEFAULT_PORT);
      command_line::add_arg(option_spec, testnet::arg_RPC_DEFAULT_PORT);
      command_line::add_arg(option_spec, testnet::arg_ZMQ_RPC_DEFAULT_PORT);
      command_line::add_arg(option_spec, testnet::arg_NETWORK_ID);
      command_line::add_arg(option_spec, testnet::arg_GENESIS_TX);
      command_line::add_arg(option_spec, testnet::arg_GENESIS_NONCE);
      command_line::add_arg(option_spec, testnet::arg_GENESIS_TIMESTAMP);

      // stagenet
      command_line::add_arg(option_spec, stagenet::arg_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, stagenet::arg_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, stagenet::arg_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, stagenet::arg_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX);
      command_line::add_arg(option_spec, stagenet::arg_P2P_DEFAULT_PORT);
      command_line::add_arg(option_spec, stagenet::arg_RPC_DEFAULT_PORT);
      command_line::add_arg(option_spec, stagenet::arg_ZMQ_RPC_DEFAULT_PORT);
      command_line::add_arg(option_spec, stagenet::arg_NETWORK_ID);
      command_line::add_arg(option_spec, stagenet::arg_GENESIS_TX);
      command_line::add_arg(option_spec, stagenet::arg_GENESIS_NONCE);
      command_line::add_arg(option_spec, stagenet::arg_GENESIS_TIMESTAMP);
  }

  void init(boost::program_options::variables_map const & vm)
  {
      CRYPTONOTE_NAME                                       = command_line::get_arg(vm, arg_CRYPTONOTE_NAME);
      COIN_NAME                                             = command_line::get_arg(vm, arg_COIN_NAME);
      MILLICOIN_NAME                                        = command_line::get_arg(vm, arg_MILLICOIN_NAME);
      MICROCOIN_NAME                                        = command_line::get_arg(vm, arg_MICROCOIN_NAME);
      NANOCOIN_NAME                                         = command_line::get_arg(vm, arg_NANOCOIN_NAME);
      PICOCOIN_NAME                                         = command_line::get_arg(vm, arg_PICOCOIN_NAME);
      CRYPTONOTE_DISPLAY_DECIMAL_POINT                      = command_line::get_arg(vm, arg_CRYPTONOTE_DISPLAY_DECIMAL_POINT);
      EMISSION_SPEED_FACTOR_PER_MINUTE                      = command_line::get_arg(vm, arg_EMISSION_SPEED_FACTOR_PER_MINUTE);
      FINAL_SUBSIDY_PER_MINUTE                              = command_line::get_arg(vm, arg_FINAL_SUBSIDY_PER_MINUTE);
      COIN                                                  = command_line::get_arg(vm, arg_COIN);
      DIFFICULTY_TARGET_V2                                  = command_line::get_arg(vm, arg_DIFFICULTY_TARGET_V2);
      DIFFICULTY_TARGET_V1                                  = command_line::get_arg(vm, arg_DIFFICULTY_TARGET_V1);
      MAX_TX_EXTRA_SIZE                                     = command_line::get_arg(vm, arg_MAX_TX_EXTRA_SIZE);
      MAX_TX_EXTRA_MSG_SIZE                                 = command_line::get_arg(vm, arg_MAX_TX_EXTRA_MSG_SIZE);
      MAX_TX_MSG_PRUNABLE_SIZE                              = command_line::get_arg(vm, arg_MAX_TX_MSG_PRUNABLE_SIZE);
      MSG_TX_AMOUNT                                         = command_line::get_arg(vm, arg_MSG_TX_AMOUNT);
      FEE_PER_KB_MESSAGE_MULTIPLIER                         = command_line::get_arg(vm, arg_FEE_PER_KB_MESSAGE_MULTIPLIER);
      CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW                  = command_line::get_arg(vm, arg_CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
      CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE                   = command_line::get_arg(vm, arg_CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE); 
      BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW                     = command_line::get_arg(vm, arg_BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW);   
      CRYPTONOTE_PRUNING_TIP_BLOCKS                         = command_line::get_arg(vm, arg_CRYPTONOTE_PRUNING_TIP_BLOCKS);

      CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX               = command_line::get_arg(vm, arg_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
      CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX       = command_line::get_arg(vm, arg_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX);
      CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX            = command_line::get_arg(vm, arg_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX);
      CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX    = command_line::get_arg(vm, arg_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX);
      P2P_DEFAULT_PORT                                      = command_line::get_arg(vm, arg_P2P_DEFAULT_PORT);
      RPC_DEFAULT_PORT                                      = command_line::get_arg(vm, arg_RPC_DEFAULT_PORT);
      ZMQ_RPC_DEFAULT_PORT                                  = command_line::get_arg(vm, arg_ZMQ_RPC_DEFAULT_PORT);
      NETWORK_ID                                            = boost::uuids::string_generator()(command_line::get_arg(vm, arg_NETWORK_ID));
      GENESIS_TX                                            = command_line::get_arg(vm, arg_GENESIS_TX);
      GENESIS_NONCE                                         = command_line::get_arg(vm, arg_GENESIS_NONCE);
      GENESIS_TIMESTAMP                                     = command_line::get_arg(vm, arg_GENESIS_TIMESTAMP);
      if(GENESIS_TIMESTAMP==0)                              GENESIS_TIMESTAMP = time(NULL);

      testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX               = command_line::get_arg(vm, testnet::arg_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
      testnet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX       = command_line::get_arg(vm, testnet::arg_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX);
      testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX            = command_line::get_arg(vm, testnet::arg_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX);
      testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX    = command_line::get_arg(vm, testnet::arg_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX);
      testnet::P2P_DEFAULT_PORT                                      = command_line::get_arg(vm, testnet::arg_P2P_DEFAULT_PORT);
      testnet::RPC_DEFAULT_PORT                                      = command_line::get_arg(vm, testnet::arg_RPC_DEFAULT_PORT);
      testnet::ZMQ_RPC_DEFAULT_PORT                                  = command_line::get_arg(vm, testnet::arg_ZMQ_RPC_DEFAULT_PORT);
      testnet::NETWORK_ID                                            = boost::uuids::string_generator()(command_line::get_arg(vm, testnet::arg_NETWORK_ID));
      testnet::GENESIS_TX                                            = command_line::get_arg(vm, testnet::arg_GENESIS_TX);
      testnet::GENESIS_NONCE                                         = command_line::get_arg(vm, testnet::arg_GENESIS_NONCE);
      testnet::GENESIS_TIMESTAMP                                     = command_line::get_arg(vm, testnet::arg_GENESIS_TIMESTAMP);
      if(testnet::GENESIS_TIMESTAMP==0)                              testnet::GENESIS_TIMESTAMP = time(NULL);

      stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX               = command_line::get_arg(vm, stagenet::arg_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
      stagenet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX       = command_line::get_arg(vm, stagenet::arg_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX);
      stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX            = command_line::get_arg(vm, stagenet::arg_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX);
      stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX    = command_line::get_arg(vm, stagenet::arg_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX);
      stagenet::P2P_DEFAULT_PORT                                      = command_line::get_arg(vm, stagenet::arg_P2P_DEFAULT_PORT);
      stagenet::RPC_DEFAULT_PORT                                      = command_line::get_arg(vm, stagenet::arg_RPC_DEFAULT_PORT);
      stagenet::ZMQ_RPC_DEFAULT_PORT                                  = command_line::get_arg(vm, stagenet::arg_ZMQ_RPC_DEFAULT_PORT);
      stagenet::NETWORK_ID                                            = boost::uuids::string_generator()(command_line::get_arg(vm, stagenet::arg_NETWORK_ID));
      stagenet::GENESIS_TX                                            = command_line::get_arg(vm, stagenet::arg_GENESIS_TX);
      stagenet::GENESIS_NONCE                                         = command_line::get_arg(vm, stagenet::arg_GENESIS_NONCE);
      stagenet::GENESIS_TIMESTAMP                                     = command_line::get_arg(vm, stagenet::arg_GENESIS_TIMESTAMP);
      if(stagenet::GENESIS_TIMESTAMP==0)                              stagenet::GENESIS_TIMESTAMP = time(NULL);
  }

  void new_network_id()
  {
      boost::uuids::random_generator g;
      NETWORK_ID = g();
  }

  void new_testnet_network_id()
  {
      boost::uuids::random_generator g;
      testnet::NETWORK_ID = g();
  }

  void new_stagenet_network_id()
  {
      boost::uuids::random_generator g;
      stagenet::NETWORK_ID = g();
  }

  bool load_config_file(const std::string& config)
  {
    boost::program_options::options_description desc_params;
    boost::program_options::variables_map vm;
    boost::filesystem::path config_path(config);
    boost::system::error_code ec;
    if (boost::filesystem::exists(config_path, ec))
    {
      init_options(desc_params);
      try
      {
        boost::program_options::store(boost::program_options::parse_config_file<char>(config_path.string<std::string>().c_str(), desc_params), vm);
      }
      catch (const boost::program_options::unknown_option &e)
      {
        std::string unrecognized_option = e.get_option_name();
        if (desc_params.find_nothrow(unrecognized_option, false))
        {
          std::cerr << "Option '" << unrecognized_option << "' is not allowed in the config file, please use it as a command line flag." << std::endl;
        }
        else
        {
          std::cerr << "Unrecognized option '" << unrecognized_option << "' in config file." << std::endl;
        }
        return false;
      }
      catch (const std::exception &e)
      {
        // log system isn't initialized yet
        std::cerr << "Error parsing config file: " << e.what() << std::endl;
        return false;
      }
    }
    else
    {
      return false;
    }
    init(vm);
    return true;
  }
}

#else

namespace config
{
  void init_options(boost::program_options::options_description & option_spec) {}
  void init(boost::program_options::variables_map const & vm) {}
  void new_network_id() {}
  void new_testnet_network_id() {}
  void new_stagenet_network_id() {}
}

#endif

namespace config
{
  crypto::hash get_cryptonote_config_hash()
  {
      crypto::hash hash[28];

      crypto::cn_fast_hash(CRYPTONOTE_NAME.c_str(), CRYPTONOTE_NAME.length(), hash[0]);
      crypto::cn_fast_hash(COIN_NAME.c_str(), COIN_NAME.length(), hash[1]);
      crypto::cn_fast_hash(MILLICOIN_NAME.c_str(), MILLICOIN_NAME.length(), hash[2]);
      crypto::cn_fast_hash(MICROCOIN_NAME.c_str(), MICROCOIN_NAME.length(), hash[3]);
      crypto::cn_fast_hash(NANOCOIN_NAME.c_str(), NANOCOIN_NAME.length(), hash[4]);
      crypto::cn_fast_hash(PICOCOIN_NAME.c_str(), PICOCOIN_NAME.length(), hash[5]);
      crypto::cn_fast_hash(&CRYPTONOTE_DISPLAY_DECIMAL_POINT, sizeof(CRYPTONOTE_DISPLAY_DECIMAL_POINT), hash[6]);
      crypto::cn_fast_hash(&COIN, sizeof(COIN), hash[7]);
      crypto::cn_fast_hash(&MSG_TX_AMOUNT, sizeof(MSG_TX_AMOUNT), hash[8]);
      crypto::cn_fast_hash(&FEE_PER_KB_MESSAGE_MULTIPLIER, sizeof(FEE_PER_KB_MESSAGE_MULTIPLIER), hash[9]);
      crypto::cn_fast_hash(&EMISSION_SPEED_FACTOR_PER_MINUTE, sizeof(EMISSION_SPEED_FACTOR_PER_MINUTE), hash[10]);
      crypto::cn_fast_hash(&FINAL_SUBSIDY_PER_MINUTE, sizeof(FINAL_SUBSIDY_PER_MINUTE), hash[11]);
      crypto::cn_fast_hash(&DIFFICULTY_TARGET_V2, sizeof(DIFFICULTY_TARGET_V2), hash[12]);
      crypto::cn_fast_hash(&DIFFICULTY_TARGET_V1, sizeof(DIFFICULTY_TARGET_V1), hash[13]);
      crypto::cn_fast_hash(&MAX_TX_EXTRA_SIZE, sizeof(MAX_TX_EXTRA_SIZE), hash[14]);
      crypto::cn_fast_hash(&MAX_TX_EXTRA_MSG_SIZE, sizeof(MAX_TX_EXTRA_MSG_SIZE), hash[15]);
      crypto::cn_fast_hash(&MAX_TX_MSG_PRUNABLE_SIZE, sizeof(MAX_TX_MSG_PRUNABLE_SIZE), hash[16]);
      crypto::cn_fast_hash(&CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, sizeof(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW), hash[17]);
      crypto::cn_fast_hash(&CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, sizeof(CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE), hash[18]);
      crypto::cn_fast_hash(&BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, sizeof(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW), hash[19]);
      crypto::cn_fast_hash(&CRYPTONOTE_PRUNING_TIP_BLOCKS, sizeof(CRYPTONOTE_PRUNING_TIP_BLOCKS), hash[20]);
      crypto::cn_fast_hash(&CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, sizeof(CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX), hash[21]);
      crypto::cn_fast_hash(&CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX, sizeof(CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX), hash[22]);
      crypto::cn_fast_hash(&CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX, sizeof(CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX), hash[23]);
      crypto::cn_fast_hash(&CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX, sizeof(CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX), hash[24]);
      crypto::cn_fast_hash(&GENESIS_NONCE, sizeof(GENESIS_NONCE), hash[25]);
      crypto::cn_fast_hash(&GENESIS_TIMESTAMP, sizeof(GENESIS_TIMESTAMP), hash[26]);
      crypto::cn_fast_hash(NETWORK_ID.data, NETWORK_ID.size(), hash[27]);

      crypto::hash r;
      crypto::tree_hash(hash, 28, r);
      return r;
  }
  crypto::hash get_testnet_cryptonote_config_hash()
  {
      crypto::hash hash[28];

      crypto::cn_fast_hash(CRYPTONOTE_NAME.c_str(), CRYPTONOTE_NAME.length(), hash[0]);
      crypto::cn_fast_hash(COIN_NAME.c_str(), COIN_NAME.length(), hash[1]);
      crypto::cn_fast_hash(MILLICOIN_NAME.c_str(), MILLICOIN_NAME.length(), hash[2]);
      crypto::cn_fast_hash(MICROCOIN_NAME.c_str(), MICROCOIN_NAME.length(), hash[3]);
      crypto::cn_fast_hash(NANOCOIN_NAME.c_str(), NANOCOIN_NAME.length(), hash[4]);
      crypto::cn_fast_hash(PICOCOIN_NAME.c_str(), PICOCOIN_NAME.length(), hash[5]);
      crypto::cn_fast_hash(&CRYPTONOTE_DISPLAY_DECIMAL_POINT, sizeof(CRYPTONOTE_DISPLAY_DECIMAL_POINT), hash[6]);
      crypto::cn_fast_hash(&COIN, sizeof(COIN), hash[7]);
      crypto::cn_fast_hash(&MSG_TX_AMOUNT, sizeof(MSG_TX_AMOUNT), hash[8]);
      crypto::cn_fast_hash(&FEE_PER_KB_MESSAGE_MULTIPLIER, sizeof(FEE_PER_KB_MESSAGE_MULTIPLIER), hash[9]);
      crypto::cn_fast_hash(&EMISSION_SPEED_FACTOR_PER_MINUTE, sizeof(EMISSION_SPEED_FACTOR_PER_MINUTE), hash[10]);
      crypto::cn_fast_hash(&FINAL_SUBSIDY_PER_MINUTE, sizeof(FINAL_SUBSIDY_PER_MINUTE), hash[11]);
      crypto::cn_fast_hash(&DIFFICULTY_TARGET_V2, sizeof(DIFFICULTY_TARGET_V2), hash[12]);
      crypto::cn_fast_hash(&DIFFICULTY_TARGET_V1, sizeof(DIFFICULTY_TARGET_V1), hash[13]);
      crypto::cn_fast_hash(&MAX_TX_EXTRA_SIZE, sizeof(MAX_TX_EXTRA_SIZE), hash[14]);
      crypto::cn_fast_hash(&MAX_TX_EXTRA_MSG_SIZE, sizeof(MAX_TX_EXTRA_MSG_SIZE), hash[15]);
      crypto::cn_fast_hash(&MAX_TX_MSG_PRUNABLE_SIZE, sizeof(MAX_TX_MSG_PRUNABLE_SIZE), hash[16]);
      crypto::cn_fast_hash(&CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, sizeof(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW), hash[17]);
      crypto::cn_fast_hash(&CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, sizeof(CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE), hash[18]);
      crypto::cn_fast_hash(&BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, sizeof(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW), hash[19]);
      crypto::cn_fast_hash(&CRYPTONOTE_PRUNING_TIP_BLOCKS, sizeof(CRYPTONOTE_PRUNING_TIP_BLOCKS), hash[20]);
      crypto::cn_fast_hash(&testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, sizeof(testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX), hash[21]);
      crypto::cn_fast_hash(&testnet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX, sizeof(testnet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX), hash[22]);
      crypto::cn_fast_hash(&testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX, sizeof(testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX), hash[23]);
      crypto::cn_fast_hash(&testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX, sizeof(testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX), hash[24]);
      crypto::cn_fast_hash(&testnet::GENESIS_NONCE, sizeof(testnet::GENESIS_NONCE), hash[25]);
      crypto::cn_fast_hash(&testnet::GENESIS_TIMESTAMP, sizeof(testnet::GENESIS_TIMESTAMP), hash[26]);
      crypto::cn_fast_hash(testnet::NETWORK_ID.data, testnet::NETWORK_ID.size(), hash[27]);

      crypto::hash r;
      crypto::tree_hash(hash, 28, r);
      return r;
  }

  crypto::hash get_stagenet_cryptonote_config_hash()
  {
      crypto::hash hash[28];

      crypto::cn_fast_hash(CRYPTONOTE_NAME.c_str(), CRYPTONOTE_NAME.length(), hash[0]);
      crypto::cn_fast_hash(COIN_NAME.c_str(), COIN_NAME.length(), hash[1]);
      crypto::cn_fast_hash(MILLICOIN_NAME.c_str(), MILLICOIN_NAME.length(), hash[2]);
      crypto::cn_fast_hash(MICROCOIN_NAME.c_str(), MICROCOIN_NAME.length(), hash[3]);
      crypto::cn_fast_hash(NANOCOIN_NAME.c_str(), NANOCOIN_NAME.length(), hash[4]);
      crypto::cn_fast_hash(PICOCOIN_NAME.c_str(), PICOCOIN_NAME.length(), hash[5]);
      crypto::cn_fast_hash(&CRYPTONOTE_DISPLAY_DECIMAL_POINT, sizeof(CRYPTONOTE_DISPLAY_DECIMAL_POINT), hash[6]);
      crypto::cn_fast_hash(&COIN, sizeof(COIN), hash[7]);
      crypto::cn_fast_hash(&MSG_TX_AMOUNT, sizeof(MSG_TX_AMOUNT), hash[8]);
      crypto::cn_fast_hash(&FEE_PER_KB_MESSAGE_MULTIPLIER, sizeof(FEE_PER_KB_MESSAGE_MULTIPLIER), hash[9]);
      crypto::cn_fast_hash(&EMISSION_SPEED_FACTOR_PER_MINUTE, sizeof(EMISSION_SPEED_FACTOR_PER_MINUTE), hash[10]);
      crypto::cn_fast_hash(&FINAL_SUBSIDY_PER_MINUTE, sizeof(FINAL_SUBSIDY_PER_MINUTE), hash[11]);
      crypto::cn_fast_hash(&DIFFICULTY_TARGET_V2, sizeof(DIFFICULTY_TARGET_V2), hash[12]);
      crypto::cn_fast_hash(&DIFFICULTY_TARGET_V1, sizeof(DIFFICULTY_TARGET_V1), hash[13]);
      crypto::cn_fast_hash(&MAX_TX_EXTRA_SIZE, sizeof(MAX_TX_EXTRA_SIZE), hash[14]);
      crypto::cn_fast_hash(&MAX_TX_EXTRA_MSG_SIZE, sizeof(MAX_TX_EXTRA_MSG_SIZE), hash[15]);
      crypto::cn_fast_hash(&MAX_TX_MSG_PRUNABLE_SIZE, sizeof(MAX_TX_MSG_PRUNABLE_SIZE), hash[16]);
      crypto::cn_fast_hash(&CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, sizeof(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW), hash[17]);
      crypto::cn_fast_hash(&CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, sizeof(CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE), hash[18]);
      crypto::cn_fast_hash(&BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, sizeof(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW), hash[19]);
      crypto::cn_fast_hash(&CRYPTONOTE_PRUNING_TIP_BLOCKS, sizeof(CRYPTONOTE_PRUNING_TIP_BLOCKS), hash[20]);
      crypto::cn_fast_hash(&stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, sizeof(stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX), hash[21]);
      crypto::cn_fast_hash(&stagenet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX, sizeof(stagenet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX), hash[22]);
      crypto::cn_fast_hash(&stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX, sizeof(stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX), hash[23]);
      crypto::cn_fast_hash(&stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX, sizeof(stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX), hash[24]);
      crypto::cn_fast_hash(&stagenet::GENESIS_NONCE, sizeof(stagenet::GENESIS_NONCE), hash[25]);
      crypto::cn_fast_hash(&stagenet::GENESIS_TIMESTAMP, sizeof(stagenet::GENESIS_TIMESTAMP), hash[26]);
      crypto::cn_fast_hash(stagenet::NETWORK_ID.data, stagenet::NETWORK_ID.size(), hash[27]);

      crypto::hash r;
      crypto::tree_hash(hash, 28, r);
      return r;
  }
}
