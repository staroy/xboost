  struct CFG {
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
                                                              =                                                                                  
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
                                                              =                                                                                  
      c_s_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX             =  U64 {config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX};
      c_s_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX  =  U64 {config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX};
      c_s_CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX     =  U64 {config::stagenet::CRYPTONOTE_PUBLIC_CHANNEL_ADDRESS_BASE58_PREFIX};
      c_s_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX          =  U64 {config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX};
      c_s_P2P_DEFAULT_PORT                                    =  int config::stagenet::P2P_DEFAULT_PORT;
      c_s_RPC_DEFAULT_PORT                                    =  int config::stagenet::RPC_DEFAULT_PORT;
      c_s_ZMQ_RPC_DEFAULT_PORT                                =  int config::stagenet::ZMQ_RPC_DEFAULT_PORT;
      c_s_NETWORK_ID                                          =  boost::lexical_cast<std::string>(config::stagenet::NETWORK_ID);
      c_s_GENESIS_TX                                          =  config::stagenet::GENESIS_TX;
      c_s_GENESIS_NONCE                                       =  U64 {config::stagenet::GENESIS_NONCE};
      c_s_GENESIS_TIMESTAMP                                   =  U64 {config::stagenet::GENESIS_TIMESTAMP};
    }
  } cfg;                                                        


auto cfg_ut = cryptonote.new_usertype<CFG>("cryptonote_config");
cfg_ut.set("objectType", sol::readonly(&CFG::c_s_GENESIS_TIMESTAMP);
