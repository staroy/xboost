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

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <boost/uuid/uuid.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include "crypto/hash.h"

#ifdef CRYPTONOTE_CONFIGURABLE
  #define DEF(type, name, val) \
     extern type name; \
     type const name##_DEFAULT = val;
#else 
  #define DEF(type, name, val) type const name = val;
#endif

#define CRYPTONOTE_DNS_TIMEOUT_MS                       20000

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_MAX_TX_SIZE                          1000000
#define CRYPTONOTE_MAX_TX_PER_BLOCK                     0x10000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER          0
DEF( uint64_t, CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,    10) //60
#define CURRENT_TRANSACTION_VERSION                     2
#define CURRENT_BLOCK_MAJOR_VERSION                     1
#define CURRENT_BLOCK_MINOR_VERSION                     0
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT              60*60*2
DEF( uint64_t, CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,     10)

DEF( uint64_t, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW,       10) //60

// MONEY_SUPPLY - total number coins to be generated
#define MONEY_SUPPLY                                    ((uint64_t)(-1))
DEF( uint64_t, EMISSION_SPEED_FACTOR_PER_MINUTE,        (20))
DEF( uint64_t, FINAL_SUBSIDY_PER_MINUTE,                ((uint64_t)300000000000)) // 3 * pow(10, 11)

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2    60000 //size of block (bytes) after which reward for block calculated using block size
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    20000 //size of block (bytes) after which reward for block calculated using block size - before first fork
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5    300000 //size of block (bytes) after which reward for block calculated using block size - second change, from v5
#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   100000 // size in blocks of the long term block weight median window
#define CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR 50
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
DEF( uint32_t, CRYPTONOTE_DISPLAY_DECIMAL_POINT,        12)
// COIN - number of smallest units in one coin
DEF( uint64_t, COIN,                                    ((uint64_t)1000000000000)) // pow(10, 12)

#define FEE_PER_KB_OLD                                  ((uint64_t)10000000000) // pow(10, 10)
#define FEE_PER_KB                                      ((uint64_t)2000000000) // 2 * pow(10, 9)
#define FEE_PER_BYTE                                    ((uint64_t)300000)
#define DYNAMIC_FEE_PER_KB_BASE_FEE                     ((uint64_t)2000000000) // 2 * pow(10,9)
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD            ((uint64_t)10000000000000) // 10 * pow(10,12)
#define DYNAMIC_FEE_PER_KB_BASE_FEE_V5                  ((uint64_t)2000000000 * (uint64_t)CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT        ((uint64_t)3000)
DEF( uint64_t, FEE_PER_KB_MESSAGE_MULTIPLIER,           5)

#define ORPHANED_BLOCKS_MAX_COUNT                       100


DEF( uint64_t, DIFFICULTY_TARGET_V2,                    120)  // seconds
DEF( uint64_t, DIFFICULTY_TARGET_V1,                    60)   // seconds - before first fork
#define DIFFICULTY_WINDOW                               720   // blocks
#define DIFFICULTY_LAG                                  15    // !!!
#define DIFFICULTY_CUT                                  60    // timestamps to cut after sorting
#define DIFFICULTY_BLOCKS_COUNT                         DIFFICULTY_WINDOW + DIFFICULTY_LAG


#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1   DIFFICULTY_TARGET_V1 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   DIFFICULTY_TARGET_V2 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1


#define DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN             DIFFICULTY_TARGET_V1 //just alias; used by tests


#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          10000  //by default, blocks ids count in synchronizing
#define BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT              25000  //max blocks ids count in synchronizing
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4       100    //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT              20     //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_MAX_COUNT                  2048   //must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                    (86400*3) //seconds, three days
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     604800 //seconds, one week


#define CRYPTONOTE_DANDELIONPP_STEMS              2 // number of outgoing stem connections per epoch
#define CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY 20 // out of 100
#define CRYPTONOTE_DANDELIONPP_MIN_EPOCH         10 // minutes
#define CRYPTONOTE_DANDELIONPP_EPOCH_RANGE       30 // seconds
#define CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE      5 // seconds average for poisson distributed fluff flush
#define CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE   39 // seconds (see tx_pool.cpp for more info)

// see src/cryptonote_protocol/levin_notify.cpp
#define CRYPTONOTE_NOISE_MIN_EPOCH                      5      // minutes
#define CRYPTONOTE_NOISE_EPOCH_RANGE                    30     // seconds
#define CRYPTONOTE_NOISE_MIN_DELAY                      10     // seconds
#define CRYPTONOTE_NOISE_DELAY_RANGE                    5      // seconds
#define CRYPTONOTE_NOISE_BYTES                          3*1024 // 3 KiB
#define CRYPTONOTE_NOISE_CHANNELS                       2      // Max outgoing connections per zone used for noise/covert sending

// Both below are in seconds. The idea is to delay forwarding from i2p/tor
// to ipv4/6, such that 2+ incoming connections _could_ have sent the tx
#define CRYPTONOTE_FORWARD_DELAY_BASE (CRYPTONOTE_NOISE_MIN_DELAY + CRYPTONOTE_NOISE_DELAY_RANGE)
#define CRYPTONOTE_FORWARD_DELAY_AVERAGE (CRYPTONOTE_FORWARD_DELAY_BASE + (CRYPTONOTE_FORWARD_DELAY_BASE / 2))

#define CRYPTONOTE_MAX_FRAGMENTS                        20 // ~20 * NOISE_BYTES max payload size for covert/noise send

#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT     1000
#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT        20000
#define MAX_RPC_CONTENT_LENGTH                          1048576 // 1 MB

#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                   5000

#define P2P_DEFAULT_CONNECTIONS_COUNT                   12
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                  60           //secondes
#define P2P_DEFAULT_PACKET_MAX_SIZE                     50000000     //50000000 bytes maximum packet size
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                  250
#define P2P_MAX_PEERS_IN_HANDSHAKE                      250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                  5000       //5 seconds
#define P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT               45         // seconds
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000       //2 seconds
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000  //2 minutes
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000       //5 seconds
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2
#define P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT       2
#define P2P_DEFAULT_LIMIT_RATE_UP                       2048       // kB/s
#define P2P_DEFAULT_LIMIT_RATE_DOWN                     8192       // kB/s

#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)     //1 hour
#define P2P_IP_BLOCKTIME                                (60*60*24)  //24 hour
#define P2P_IP_FAILS_BEFORE_BLOCK                       10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL               (5*60) //5 minutes

#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                  0x01
#define P2P_SUPPORT_FLAGS                               P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

#define RPC_IP_FAILS_BEFORE_BLOCK                       3

DEF( std::string, CRYPTONOTE_NAME,              "xboost")
DEF( std::string, COIN_NAME,                    "XBC")
DEF( std::string, MILLICOIN_NAME,               "milliXBC")
DEF( std::string, MICROCOIN_NAME,               "microXBC")
DEF( std::string, NANOCOIN_NAME,                "nanoXBC")
DEF( std::string, PICOCOIN_NAME,                "picoXBC")

#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME      "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME "lock.mdb"
#define P2P_NET_DATA_FILENAME                   "p2pstate.bin"
#define RPC_PAYMENTS_DATA_FILENAME              "rpcpayments.bin"
#define MINER_CONFIG_FILE_NAME                  "miner_conf.json"

#define THREAD_STACK_SIZE                       5 * 1024 * 1024

#define HF_VERSION_DYNAMIC_FEE                  4
#define HF_VERSION_MIN_MIXIN_4                  6
#define HF_VERSION_MIN_MIXIN_6                  7
#define HF_VERSION_MIN_MIXIN_10                 8
#define HF_VERSION_MIN_MIXIN_15                 15
#define HF_VERSION_ENFORCE_RCT                  6
#define HF_VERSION_PER_BYTE_FEE                 8
#define HF_VERSION_SMALLER_BP                   10
#define HF_VERSION_LONG_TERM_BLOCK_WEIGHT       10
#define HF_VERSION_MIN_2_OUTPUTS                12
#define HF_VERSION_MIN_V2_COINBASE_TX           12
#define HF_VERSION_SAME_MIXIN                   12
#define HF_VERSION_REJECT_SIGS_IN_COINBASE      12
#define HF_VERSION_ENFORCE_MIN_AGE              12
#define HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY 12
#define HF_VERSION_EXACT_COINBASE               13
#define HF_VERSION_CLSAG                        13
#define HF_VERSION_DETERMINISTIC_UNLOCK_TIME    13
#define HF_VERSION_BULLETPROOF_PLUS             15
#define HF_VERSION_VIEW_TAGS                    15
#define HF_VERSION_2021_SCALING                 15

#define PER_KB_FEE_QUANTIZATION_DECIMALS        8
#define CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES 2

#define HASH_OF_HASHES_STEP                     512

#define DEFAULT_TXPOOL_MAX_WEIGHT               648000000ull // 3 days at 300000, in bytes

#define BULLETPROOF_MAX_OUTPUTS                 16
#define BULLETPROOF_PLUS_MAX_OUTPUTS            16

#define CRYPTONOTE_PRUNING_STRIPE_SIZE          4096 // the smaller, the smoother the increase
#define CRYPTONOTE_PRUNING_LOG_STRIPES          3 // the higher, the more space saved
DEF( uint64_t,  CRYPTONOTE_PRUNING_TIP_BLOCKS,  5500) // the smaller, the more space saved

#define RPC_CREDITS_PER_HASH_SCALE ((float)(1<<24))

#define DNS_BLOCKLIST_LIFETIME (86400 * 8)

//The limit is enough for the mandatory transaction content with 16 outputs (547 bytes),
//a custom tag (1 byte) and up to 32 bytes of custom data for each recipient.
// (1+32) + (1+1+16*32) + (1+16*32) = 1060
DEF( uint64_t,  MAX_TX_EXTRA_SIZE,              2048 + 1060)
DEF( uint64_t,  MAX_TX_EXTRA_MSG_SIZE,          256)
DEF( uint64_t,  MAX_TX_MSG_PRUNABLE_SIZE,       8192)
DEF( uint64_t,  MSG_TX_AMOUNT,                  1000)

#define MSG_TX_EXTRA_TYPE                       100
#define MSG_TX_EXTRA_FREQ_0                     0

// used to choose atomic swap message type
#define ATOMIC_SWAP_MSG_TX_EXTRA_TYPE           (MSG_TX_EXTRA_TYPE + 1)
#define ATOMIC_SWAP_HASH_X_UNLOCK_TIME          (CRYPTONOTE_MAX_BLOCK_NUMBER - 1)

// New constants are intended to go here
namespace config
{
  uint64_t const DEFAULT_FEE_ATOMIC_XMR_PER_KB = 500; // Just a placeholder!  Change me!
  uint8_t const FEE_CALCULATION_MAX_RETRIES = 10;
  uint64_t const DEFAULT_DUST_THRESHOLD = ((uint64_t)2000000000); // 2 * pow(10, 9)
  uint64_t const BASE_REWARD_CLAMP_THRESHOLD = ((uint64_t)100000000); // pow(10, 8)

  DEF(uint64_t, CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, 17)
  DEF(uint64_t, CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX, 18)
  DEF(uint64_t, CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX, 19)
  DEF(uint64_t, CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX, 41)
  DEF(uint16_t, P2P_DEFAULT_PORT, 11080)
  DEF(uint16_t, RPC_DEFAULT_PORT, 11081)
  DEF(uint16_t, ZMQ_RPC_DEFAULT_PORT, 11082)
  #define sz_NETWORK_ID_0_DEFAULT "1741eaa7-1635-420c-9f60-9c606c0d5c49"
  // ID_0 = (boost::uuids::string_generator()(sz_NETWORK_ID_DEFAULT))
  #define ID_0 { { 0x17, 0x41, 0xea, 0xa7, 0x16, 0x35, 0x42, 0xc, 0x9f, 0x60, 0x9c, 0x60, 0x6c, 0xd, 0x5c, 0x49 } }
  DEF(boost::uuids::uuid, NETWORK_ID, ID_0)
  DEF(std::string, GENESIS_TX, "010a01ff0091b0205ab85c7e6dad0c3f869ff0a9a6d1aeb7c4d5c796baf9cda0e698d4a73a6690677d3156cab8add79506ffee849ef1188b4cfa7961b5cf84bd8d42e1292600bedede50916b4227d672d115542e3332696d01ec77bc61e75bad45e3d4eef102c5d73aababa89f820ff12110abdf8cbba41b128952bff878cf6bb7f88c00670f57c3493bd2c77fc3080bad387053846eb7b49681c7737dfa91a41caf63aa188a73d90f62ffd40c6d556614d0c343f73c055c5fd4c498f04ae0bfa05fd655390182454b6010e14faafe17d60e00282992f05abaf3c3a65ee23031a98706db240906ff9fdb580240e7e844d8555139312fd8215b364c69a8390137352ffb71a16a9166c40f373f80a8d6b907022aa25fdccc8f673f33f45897b44306a959830f1c63b2741022477a0fc8aad71c8088aca3cf02025d688f9f1bfa3cd92cae0b4ad2fb7763c73a0fed8083b0f44818dabb8ec632988090cad2c60e021904dc19877dc34b7972eee48e68e9a55aab79980452902b05bc295260c3663580e08d84ddcb01024238053f48651d884233ff6832cebf66bef2cedcca2355ec3ad67e8c7c4cf07f80c0caf384a30202e443fe974f48cb47cf4aa0657d9748aee2505aaaabae0f01ae154b87c0b741f32101f387d265917c31e7be88f790db7e202c9ab953704017ab147e8a9b16a82e639f")
  DEF(uint32_t, GENESIS_NONCE, 10000)
  DEF(uint64_t, GENESIS_TIMESTAMP, 0)

  // Hash domain separators
  const char HASH_KEY_BULLETPROOF_EXPONENT[] = "bulletproof";
  const char HASH_KEY_BULLETPROOF_PLUS_EXPONENT[] = "bulletproof_plus";
  const char HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT[] = "bulletproof_plus_transcript";
  const char HASH_KEY_RINGDB[] = "ringdsb";
  const char HASH_KEY_SUBADDRESS[] = "SubAddr";
  const unsigned char HASH_KEY_ENCRYPTED_PAYMENT_ID = 0x8d;
  const unsigned char HASH_KEY_WALLET = 0x8b;
  const unsigned char HASH_KEY_WALLET_CACHE = 0x8c;
  const unsigned char HASH_KEY_RPC_PAYMENT_NONCE = 0x57;
  const unsigned char HASH_KEY_MEMORY = 'k';
  const unsigned char HASH_KEY_MULTISIG[] = {'M', 'u', 'l', 't' , 'i', 's', 'i', 'g', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const unsigned char HASH_KEY_MULTISIG_KEY_AGGREGATION[] = "Multisig_key_agg";
  const unsigned char HASH_KEY_CLSAG_ROUND_MULTISIG[] = "CLSAG_round_ms_merge_factor";
  const unsigned char HASH_KEY_TXPROOF_V2[] = "TXPROOF_V2";
  const unsigned char HASH_KEY_CLSAG_ROUND[] = "CLSAG_round";
  const unsigned char HASH_KEY_CLSAG_AGG_0[] = "CLSAG_agg_0";
  const unsigned char HASH_KEY_CLSAG_AGG_1[] = "CLSAG_agg_1";
  const char HASH_KEY_MESSAGE_SIGNING[] = "LidMessageSignature";
  const unsigned char HASH_KEY_MM_SLOT = 'm';
  const constexpr char HASH_KEY_MULTISIG_TX_PRIVKEYS_SEED[] = "multisig_tx_privkeys_seed";
  const constexpr char HASH_KEY_MULTISIG_TX_PRIVKEYS[] = "multisig_tx_privkeys";
  const constexpr char HASH_KEY_TXHASH_AND_MIXRING[] = "txhash_and_mixring";

  // Multisig
  const uint32_t MULTISIG_MAX_SIGNERS{16};

  namespace testnet
  {
    DEF(uint64_t, CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, 52)
    DEF(uint64_t, CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX, 53)
    DEF(uint64_t, CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX, 54)
    DEF(uint64_t, CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX, 62)
    DEF(uint16_t, P2P_DEFAULT_PORT, 21080)
    DEF(uint16_t, RPC_DEFAULT_PORT, 21081)
    DEF(uint16_t, ZMQ_RPC_DEFAULT_PORT, 21082)
    #define sz_NETWORK_ID_1_DEFAULT "c18fe00a-37f8-49fa-a582-3380cc689cb9"
    // ID_1 = boost::uuids::string_generator()(sz_NETWORK_ID_DEFAULT)
    #define ID_1 { { 0xc1, 0x8f, 0xe0, 0xa, 0x37, 0xf8, 0x49, 0xfa, 0xa5, 0x82, 0x33, 0x80, 0xcc, 0x68, 0x9c, 0xb9 } }
    DEF(boost::uuids::uuid, NETWORK_ID, ID_1)
    DEF(std::string, GENESIS_TX, "010a01ff00f8afd9305aedd3c9fb0bafd920df351853399388092583c37eea45e8174692ca4c2e43e963dbf380b8504254a27751a6360480c40ba8033424b49f253c6babcd0064583ca82e6264d3295338c5d4f6a781c51f69fa39c947e211f4d7f95fd40f04e2066c8c99b907d51fe6bf2cc1b7c994be78712344981ddeb5149cfa21a0290160c1cf59eb4f0d0cc50309ca6a9d9bab7c39b3b66a217eb30b2b93ba416500727511ef0ea988f2c05454b6bb8de921b9fa20bd0ae1c1ba4232f15fe9da53080c2de25e9e66013e140b4805ea25019c4152ae5a8f77f4a8074c87f341897b370806ff9fdb5802fc2d85084e6780ab465f56b3be1c34c63a20d8d17d6cc9e435b8f59349cd4f7880a8d6b90702fa08b9b53298c0e5958997bd6acb7bb8c1911137bc2daf5f6da9d9cdd57c01308088aca3cf020254312f94c0474d88d3a4a0662e6c3678c35600ad8db12423353b97f4bec7cf3f8090cad2c60e020958f80397154f5c93b1c03285bf61e8050ebb51d0dcc3e93621cac624d4369780e08d84ddcb0102b069276f77339d299513c8d35a5dcaa99da12209b5199c2f4de4bf3bcdb8dd1880c0caf384a30202825eeb59f7d2ddbf45bbdaa9fda7d5fde948f74469370447ca1bc8b39f4482002101bfefd9a9e55e51ea60b32d82e749ec3680ee2697793c8e3ef8f298234968a856")
    DEF(uint32_t, GENESIS_NONCE, 10001)
    DEF(uint64_t, GENESIS_TIMESTAMP, 0)
  }

  namespace stagenet
  {
    DEF(uint64_t, CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, 23)
    DEF(uint64_t, CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX, 24)
    DEF(uint64_t, CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX, 25)
    DEF(uint64_t, CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX, 35)
    DEF(uint16_t, P2P_DEFAULT_PORT, 31080)
    DEF(uint16_t, RPC_DEFAULT_PORT, 31081)
    DEF(uint16_t, ZMQ_RPC_DEFAULT_PORT, 31082)
    #define sz_NETWORK_ID_2_DEFAULT "80405031-3c35-4062-8f89-13019eb19ada"
    // ID_2 = boost::uuids::string_generator()(sz_NETWORK_ID_DEFAULT)
    #define ID_2 { { 0x80, 0x40, 0x50, 0x31, 0x3c, 0x35, 0x40, 0x62, 0x8f, 0x89, 0x13, 0x1, 0x9e, 0xb1, 0x9a, 0xda } }
    DEF(boost::uuids::uuid, NETWORK_ID, ID_2)
    DEF(std::string, GENESIS_TX, "010a01ff003c042c5085e3a35ea21f1e481fb382bf2b259c22bf34727b2b61cab773db24adf2379b6e3cfe9b1629cba8c68f3a07495713ecd5b2d471db6b0d9c7f9484ed4f00fb3d78ca69a4ad4483c551f057b4945d17b239de855d0d05e06d20b6225539086c9b4ff73955c38538cb08e419e426cea5346c4d5c1af2bcd1591cdb0363650b173b7a331f2e13b86e3a216954d0c8e2764ebe67d87913ac9b6644ebda231ac6701fd20f58bba8c59a881d6b9b80ad980444edef51db92017ef7a0598620af076998a47ef9cc4e9d91faaf9abbf29fdd52e8e8204c58303ae38aa1a1a6edcf0e06ff9fdb5802e087c32a989ba18a281389bda94041cfad5d88a3dc9e7ccb7ae0ca73320aa60680a8d6b907029d93736aa05fce531256bc6ef4c2f67893b66b4de8eb7bc03c00c52f6edabd4c8088aca3cf0202aefdb00413b131d0d8fb0974832fe0c38181c1fbb376aa4e9452b5df9d4ad2258090cad2c60e0224e26917a3eab8d46a19fe1e8bb2053258523fd06dc45617cb8b65c6cc278a4980e08d84ddcb01028b57ba672760980ca93e02eb9116f229016b4b21018adf0fe09b8bdbee9cc8bc80c0caf384a302028367b09209ffa168e9858b194898347b43e8627130cf32c89f7022599acb04a12101de0cbdd8fe46ebf0d318ccedb92d33b2ae0626255e77a02059925168b0310a9a")
    DEF(uint32_t, GENESIS_NONCE, 10002)
    DEF(uint64_t, GENESIS_TIMESTAMP, 0)
  }
  void init_options(boost::program_options::options_description & option_spec);
  void init(boost::program_options::variables_map const & vm);
  void new_network_id();
  void new_testnet_network_id();
  void new_stagenet_network_id();
  crypto::hash get_cryptonote_config_hash();
  crypto::hash get_testnet_cryptonote_config_hash();
  crypto::hash get_stagenet_cryptonote_config_hash();
  bool load_config_file(const std::string& config);
}

namespace cryptonote
{
  enum network_type : uint8_t
  {
    MAINNET = 0,
    TESTNET,
    STAGENET,
    FAKECHAIN,
    UNDEFINED = 255
  };
  struct config_t
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
    uint16_t const P2P_DEFAULT_PORT;
    uint16_t const RPC_DEFAULT_PORT;
    uint16_t const ZMQ_RPC_DEFAULT_PORT;
    boost::uuids::uuid const NETWORK_ID;
    std::string const GENESIS_TX;
    uint32_t const GENESIS_NONCE;
  };
  inline const config_t& get_config(network_type nettype)
  {
    static const config_t mainnet = {
      ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX,
      ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::P2P_DEFAULT_PORT,
      ::config::RPC_DEFAULT_PORT,
      ::config::ZMQ_RPC_DEFAULT_PORT,
      ::config::NETWORK_ID,
      ::config::GENESIS_TX,
      ::config::GENESIS_NONCE
    };
    static const config_t testnet = {
      ::config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::testnet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX,
      ::config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::testnet::P2P_DEFAULT_PORT,
      ::config::testnet::RPC_DEFAULT_PORT,
      ::config::testnet::ZMQ_RPC_DEFAULT_PORT,
      ::config::testnet::NETWORK_ID,
      ::config::testnet::GENESIS_TX,
      ::config::testnet::GENESIS_NONCE
    };
    static const config_t stagenet = {
      ::config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::stagenet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX,
      ::config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::stagenet::P2P_DEFAULT_PORT,
      ::config::stagenet::RPC_DEFAULT_PORT,
      ::config::stagenet::ZMQ_RPC_DEFAULT_PORT,
      ::config::stagenet::NETWORK_ID,
      ::config::stagenet::GENESIS_TX,
      ::config::stagenet::GENESIS_NONCE
    };
    switch (nettype)
    {
      case MAINNET: return mainnet;
      case TESTNET: return testnet;
      case STAGENET: return stagenet;
      case FAKECHAIN: return mainnet;
      default: throw std::runtime_error("Invalid network type");
    }
  };
}
