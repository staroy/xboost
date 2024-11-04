local JSON = require("JSON")

local MSG_TX_EXTRA_TYPE = 100
local MSG_TX_EXTRA_FREQ_0 = 0

-- used to choose atomic swap message type
local ATOMIC_SWAP_MSG_TX_EXTRA_TYPE = MSG_TX_EXTRA_TYPE+1
local ATOMIC_SWAP_HASH_X_UNLOCK_TIME = tools.uint64_t("499999999")

local MSG_TX_AMOUNT = tools.uint64_t("1000000000000")

local MIXIN_COUNT = 15
local PRIORITY = 0

local DIFFICULTY_TARGET = 10*1000

local AST_T1 = 20
local AST_T2 = 40

local SHARED_TIMEOUT_REFRESH = DIFFICULTY_TARGET * 2
local SHARED_WAIT_TIMES = AST_T1 * DIFFICULTY_TARGET / SHARED_TIMEOUT_REFRESH
local BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW = 10

local DB = LDB(tools.wallet:get_wallet_name()..".ast")

local atomic_swap = {
  _is_listen = false,
  _chat = {
    _txids = DB["chat.txids"]
  },
  _hash_x = DB["hash_x"],
  _second_n = 3,
  _step = 0,
  _event = ""
}

function atomic_swap._chat:is_txid_exist(txid)
  local rc, ok = self._txids:get(txid)
  if rc and ok then
    return true
  end
  self._txids[txid] = true
  return false
end

function atomic_swap:is_hash_x_exist(HX)
  local rc, ok = self._hash_x:get(HX)
  if rc and ok then
    return true
  end
  self._hash_x[HX] = true
  return false
end

function open_or_create_shared_wallet(Ks_spend, Ks_view)

  local name = crypto.cn_fast_hash(Ks_spend:data()):to_hex()
  local pwd = crypto.cn_fast_hash(Ks_view:data()):to_hex()

  --[[print("name: "..name)
  print("pwd: "..pwd)
  print("Ks_spend: "..Ks_spend:to_hex())
  print("Ks_view: "..Ks_view:to_hex())]]

  local w = tools.wallet2();

  --print("open_or_create")

  w:open_or_create(name, pwd, Ks_spend, Ks_view);

  local ring_database = tools.wallet:get_ring_database()
  print("ring_database: ", ring_database)
  w:set_ring_database(ring_database)

  local ok, height, err = w:get_daemon_blockchain_height()
  if ok then
    print("daemon height", height)
    w:set_refresh_from_block_height(height)
  else
    print("error daemon height", err)
    return
  end

  print("success wallet: "..name)

  return w
end

-- pars = { addr, addr2, HX, Cx_pub, Ks_spend, Ks_view }
function atomic_swap:send_HX_to_acceptor(pars)

  local root = self

  if not root._is_listen then
    root._event = "Acceptor not listen atomic swal requests..."
    print(root._event)
    return
  end

  local Ax_sec, Ax_pub = crypto.generate_keys()
  local At_sec, At_pub = crypto.generate_keys()
  
  root.AReceiver = {
    from_addr = pars.addr,
    amount = pars.amount,
    HX = pars.HX,
    Cx_pub = pars.Cx_pub,
    Ks_spend = pars.Ks_spend,
    Ks_view = pars.Ks_view,
    Ax_sec = Ax_sec,
    Ax_pub = Ax_pub,
    At_sec = At_sec,
    At_pub = At_pub,
  }

  function root._zyre:send_X_to_acceptor(X)
    root:acceptor_transfer_locked_coin_from_shared(X)
  end

  root._shared = open_or_create_shared_wallet(pars.Ks_spend, pars.Ks_view)

  print("acceptor receiver address = "..cryptonote.get_account_address_as_str(tools.wallet:get_address(), false))

  print("AReceiver = {")
  print("  from_addr = "..cryptonote.get_account_address_as_str(pars.addr, false))
  print("  amount = "..pars.amount:print_money())
  print("  HX = "..pars.HX:to_hex())
  print("  Cx_pub = "..pars.Cx_pub:to_hex())
  print("  Ks_spend = "..pars.Ks_spend:to_hex())
  print("  Ks_view = "..pars.Ks_view:to_hex())
  print("}")

  local pars2 = {
    to_addr = pars.addr2,
    amount = pars.amount,
    HX = pars.HX,
    Cx_pub = pars.Cx_pub,
    Ks_spend = pars.Ks_spend,
    Ks_view = pars.Ks_view,
    Ax_sec = Ax_sec,
    Ax_pub = Ax_pub,
    At_sec = At_sec,
    At_pub = At_pub,
  }

  root._zyre:send_HX_to_acceptor_second(pars2, function(addr2)

    local from_addr2 = cryptonote.get_account_address_as_str(addr2, false)
    
    local data = string.format(
      "{\"class\":\"atomic_swap\",\"method\":\"send_Ax_to_creator\",\"params\":{\"from_addr2\":\"%s\",\"Ax_pub\":\"%s\"}}",
      from_addr2, root.AReceiver.Ax_pub:to_hex())
    
    tools.wallet:do_message_chat_send(
      root.AReceiver.from_addr,
      data,
      false, -- enable_comments
      MSG_TX_AMOUNT, -- amount
      false, -- unprunable
      ATOMIC_SWAP_MSG_TX_EXTRA_TYPE,
      MSG_TX_EXTRA_FREQ_0)
    
    print("send_Ax_to_creator ...")

    root:acceptor_wait_transfer_locked_coin_on_shared()

  end)

end

function atomic_swap:acceptor_wait_transfer_locked_coin_on_shared()

  print("acceptor_wait_transfer_locked_coin_on_shared ...")

  local root = self
  local refresh_n = 0
  -- check transaction
  timeout(SHARED_TIMEOUT_REFRESH, function()

    local loop = refresh_n < SHARED_WAIT_TIMES or false
    refresh_n = refresh_n + 1

    print("shared refresh ...")
    root._shared:refresh()

    for _, td in ipairs(root._shared:get_transfers()) do

      local extra = td.tx.extra
      local height = td.height
      local txid = td.txid
      local amount = td.amount
      local xx, HX, unlock_time = extra:get_hash_x()
      local px, Ax_pub = extra:get_pubkey_x()
      local pt, Ct_pub = extra:get_pubkey_t()

      if td.tx.unlock_time == ATOMIC_SWAP_HASH_X_UNLOCK_TIME  and
         root.AReceiver.amount <= amount              and
         xx and root.AReceiver.HX     == HX           and
         px and root.AReceiver.Ax_pub == Ax_pub       and
         pt and height + AST_T1 == unlock_time

      then

        print("height:      ", height)
        print("txid:        ", txid)
        print("amount:      ", amount:print_money())
        print("unlock_time: ", unlock_time)
        print("HX:          ", HX)
        print("Ax_pub:      ", Ax_pub)

        print("Received locked transfer")

        root._zyre:acceptor_transfer_locked_coin_to_shared()

        loop = false

      else

        print("tx.height:      ", height)
        print("tx.txid:        ", txid)
        print("tx.amount:      ", amount:print_money()   ,  ", expect: ",   root.AReceiver.amount:print_money() )
        print("tx.unlock_time: ", unlock_time            ,  ", expect: ",   height + AST_T1                     )
        print("         types: ", type(unlock_time)      ,  ",         ",   type(height + AST_T1)               )
        print("tx.HX:          ", HX                     ,  ", expect: ",   root.AReceiver.HX                   )
        print("tx.Ax_pub:      ", Ax_pub                 ,  ", expect: ",   root.AReceiver.Ax_pub               )
        print("tx.Ct_pub:      ", Ct_pub                 ,  ", expect: ",   root.AReceiver.Ct_pub               )

      end

    end
    return loop
  end)

end

function atomic_swap:send_Ax_to_creator(pars)
  self.CSender.Ax_pub = pars.Ax_pub

  self._step = 2
  self._event = [[2. Creator receive reply from acceptor ...]]

  print("CSender = {")
  print("  Ax_pub = "..self.CSender.Ax_pub:to_hex())
  print("}")

  self._zyre:send_Ax_to_creator_second(pars)

  -- first transfer
  self:creator_transfer_locked_coin_to_shared()
end

function atomic_swap:on_message_chat_received(height, txid, mtype, freq, chat, n, sender, data, enable_comments, timestamp, parent)
  if mtype == ATOMIC_SWAP_MSG_TX_EXTRA_TYPE and freq == MSG_TX_EXTRA_FREQ_0 then
    if not self._chat:is_txid_exist(txid) then
      local info = JSON:decode(data)
      if info.class == "atomic_swap" and info.method == "send_HX_to_acceptor" then
        local ok, addr2 = cryptonote.get_account_address_from_str(info.params.addr2)
        if not ok then
          print("Error address: "..info.params.addr2.." (on_message_chat_received)")
          return
        end
        self:send_HX_to_acceptor({
          addr = sender,
          addr2 = addr2.address,
          amount = tools.uint64_t(info.params.amount),
          HX = crypto.hash(info.params.HX),
          Cx_pub = crypto.public_key(info.params.Cx_pub),
          Ks_spend = crypto.secret_key(info.params.Ks_spend),
          Ks_view = crypto.secret_key(info.params.Ks_view)
        })
        return
      elseif info.class == "atomic_swap" and info.method == "send_Ax_to_creator" then
        local ok, from_addr2 = cryptonote.get_account_address_from_str(info.params.from_addr2)
        if not ok then
          print("Error address: "..info.params.from_addr2.." (on_message_chat_received)")
          return
        end
        self:send_Ax_to_creator({
          from_addr2 = from_addr2.address,
          Ax_pub = crypto.public_key(info.params.Ax_pub)
        })
        return
      end
      print("unqnow message: "..data)
    end
  end
end

function atomic_swap:init(_zyre)

  local root = self
  root._zyre = _zyre

  function tools.wallet:atomic_swap_second_enable(check)
    root._is_listen = check
    if check then
      function root._zyre:is_atomic_swap_second_enabled(name)
        return root._is_listen
      end
    else
      root._zyre.is_atomic_swap_second_enabled = false
      root._event = "/clear"
    end
  end

  timeout(1000, function()
    if root._second_n < 3 then
      root._second_n = root._second_n + 1
    end
    root._zyre:is_atomic_swap_second_enabled("X", function(e)
      if e then
        root._second_n = 0
      end
    end)
    return true
  end)

  function tools.wallet:atomic_swap_enabled()
    return root._second_n < 2
  end

  function root._zyre:send_Ax_to_creator_second(pars)
    root.CReceiver.from_addr = pars.from_addr2
    root.CReceiver.Ax_pub = pars.Ax_pub

    print("creator receiver address = "..cryptonote.get_account_address_as_str(tools.wallet:get_address(), false))

    print("CReceiver = {")
    print("  from_addr = "..cryptonote.get_account_address_as_str(root.CReceiver.from_addr, false))
    print("  Ax_pub = "..root.CReceiver.Ax_pub:to_hex())
    print("}")
  end

  function root._zyre:start_atomic_swap_second(pars)

    root.CReceiver = {
      amount = pars.amount,
      X = pars.X, HX = pars.HX,
      Cx_sec = pars.Cx_sec,
      Cx_pub = pars.Cx_pub,
      Ct_sec = pars.Ct_sec,
      Ct_pub = pars.Ct_pub,
      Ks_spend = pars.Ks_spend,
      Ks_view = pars.Ks_view,
    }

    root._event = "1. Creator start atomic swap ..."

    root._shared = open_or_create_shared_wallet(pars.Ks_spend, pars.Ks_view)

    print("CReceiver = {")
    print("  amount = "..root.CReceiver.amount:print_money())
    print("  X = "..epee.to_hex(root.CReceiver.X))
    print("  HX = "..root.CReceiver.HX:to_hex())
    print("  Cx_sec = "..root.CReceiver.Cx_sec:to_hex())
    print("  Cx_pub = "..root.CReceiver.Cx_pub:to_hex())
    print("  Ct_sec = "..root.CReceiver.Ct_sec:to_hex())
    print("  Ct_pub = "..root.CReceiver.Ct_pub:to_hex())
    print("  Ks_spend = "..root.CReceiver.Ks_spend:to_hex())
    print("  Ks_view = "..root.CReceiver.Ks_view:to_hex())
    print("}")

    return tools.wallet:get_address()
  end

  function root._zyre:send_HX_to_acceptor_second(pars)
    
    root.ASender = {
      to_addr = pars.to_addr,
      HX = pars.HX,
      amount = pars.amount,
      Cx_pub = pars.Cx_pub,
      Ks_spend = pars.Ks_spend,
      Ks_view = pars.Ks_view,
      Ax_sec = pars.Ax_sec,
      Ax_pub = pars.Ax_pub,
      At_sec = pars.At_sec,
      At_pub = pars.At_pub,
    }

    root._shared = open_or_create_shared_wallet(pars.Ks_spend, pars.Ks_view)
    
    print("acceptor sender address = "..cryptonote.get_account_address_as_str(tools.wallet:get_address(), false))

    print("ASender = {")
    print("  to_addr = "..cryptonote.get_account_address_as_str(root.ASender.to_addr, false))
    print("  HX = "..root.ASender.HX:to_hex())
    print("  amount = "..root.ASender.amount:print_money())
    print("  Cx_pub = "..root.ASender.Cx_pub:to_hex())
    print("  Ks_spend = "..root.ASender.Ks_spend:to_hex())
    print("  Ks_view = "..root.ASender.Ks_view:to_hex())
    print("  Ax_sec = "..root.ASender.Ax_sec:to_hex())
    print("  Ax_pub = "..root.ASender.Ax_pub:to_hex())
    print("  At_sec = "..root.ASender.At_sec:to_hex())
    print("  At_pub = "..root.ASender.At_pub:to_hex())
    print("}")

    function tools.wallet:on_atomic_swap_x_received(txid, X)
      local HX = crypto.cn_fast_hash(X)
      if not root:is_hash_x_exist(HX) then
        print("== on_atomic_swap_x_received ==")
        print("txid:", txid)
        print("X:", epee.to_hex(X))
        print("HX:", HX)
        root._zyre:send_X_to_acceptor(X)
      end
    end
    
    return tools.wallet:get_address()
  end

  function tools.wallet:start_atomic_swap(destinations, payment_id, amounts, mixin_count, priority, message, unprunable)

    root._step = 1

    if #destinations ~= 1 or #amounts ~= 1 then
      print("destinations and amounts must be 1 dimensions")
      return
    end

    print("Start atomic swap ...")
    print("from address: ", cryptonote.get_account_address_as_str(tools.wallet:get_address(), false))
    print("mixin_count: ", mixin_count)
    print("priority: ", priority)
    --print("payment_id: ", payment_id)
    --print("addresses: "..destinations[1])
    print("amounts: "..amounts[1]:print_money())
    print("message: ", message)
    print("unprunable: ", unprunable)

    local X = crypto.rand(32)
    local HX = crypto.cn_fast_hash(X)
    local Cx_sec, Cx_pub = crypto.generate_keys()
    local Ct_sec, Ct_pub = crypto.generate_keys()
    local Ks_spend = crypto.generate_keys()
    local Ks_view = crypto.generate_keys()

    local ok, info = cryptonote.get_account_address_from_str(destinations[1])
    if not ok then
      print("Error address: "..destinations[1].." (start_atomic_swap)")
      return
    end

    root.CSender = {
      to_addr = info.address,
      amount = amounts[1],
      X = X, HX = HX,
      Cx_sec = Cx_sec, Cx_pub = Cx_pub,
      Ct_sec = Ct_sec, Ct_pub = Ct_pub,
      Ks_spend = Ks_spend, Ks_view = Ks_view,
      priority = priority, mixin_count = mixin_count
    }

    root._shared = open_or_create_shared_wallet(Ks_spend, Ks_view)

    print("CSender = {")
    print("  to_addr = "..destinations[1])
    print("  amount = "..root.CSender.amount:print_money())
    print("  X = "..epee.to_hex(X))
    print("  HX = "..HX:to_hex())
    print("  Cx_sec = "..Cx_sec:to_hex())
    print("  Cx_pub = "..Cx_pub:to_hex())
    print("  Ct_sec = "..Ct_sec:to_hex())
    print("  Ct_pub = "..Ct_pub:to_hex())
    print("  Ks_spend = "..Ks_spend:to_hex())
    print("  Ks_view = "..Ks_view:to_hex())
    print("}")

    local pars2 = {
      amount = root.CSender.amount,
      X = X, HX = HX,
      Cx_sec = Cx_sec, Cx_pub = Cx_pub,
      Ct_sec = Ct_sec, Ct_pub = Ct_pub,
      Ks_spend = Ks_spend, Ks_view = Ks_view
    }

    root._zyre:start_atomic_swap_second(pars2, function(addr2)

      local addr2 = cryptonote.get_account_address_as_str(addr2, false)
      
      local data = string.format(
        "{\"class\":\"atomic_swap\",\"method\":\"send_HX_to_acceptor\",\"params\":{\"addr2\":\"%s\",\"amount\":\"%s\",\"HX\":\"%s\",\"Cx_pub\":\"%s\",\"Ks_spend\":\"%s\",\"Ks_view\":\"%s\"}}",
        addr2, root.CSender.amount, HX:to_hex(), Cx_pub:to_hex(), Ks_spend:to_hex(), Ks_view:to_hex())
      
      tools.wallet:do_message_chat_send(
        info.address,
        data,
        false, -- enable_comments
        MSG_TX_AMOUNT, -- amount
        false, -- unprunable
        ATOMIC_SWAP_MSG_TX_EXTRA_TYPE,
        MSG_TX_EXTRA_FREQ_0)
      
      print("send_HX_to_acceptor ...")

      root._event = "1. Creator send hello to acceptor..."

    end)

  end


  function tools.wallet:atomic_swap_in_process()
    if root._step > 0 then
      return true
    end
    return false
  end

  function tools.wallet:atomic_swap_get_notify()
    local e = root._event
    root._event = ""
    return e
  end

  function root._zyre:acceptor_transfer_locked_coin_to_shared()
    root:acceptor_transfer_locked_coin_to_shared()
  end

  function root._zyre:creator_wait_transfer_locked_coin_on_shared()
    root:creator_wait_transfer_locked_coin_on_shared()
  end

end

function atomic_swap:calculate_reserved_fee_for_shared()

  local extra = cryptonote.tx_extra_data.new()

  local X = crypto.rand(32)
  local sign = crypto.signature();
  local pubkey = crypto.public_key()

  extra:set_x(X)
  extra:set_sign_x(sign)
  extra:set_pubkey_x(pubkey)

  local use_per_byte_fee = true
  local use_rct = true
  local n_inputs = 1
  local mixin = 0
  local n_outputs = 2
  local extra_size = extra:length()
  local bulletproof = true
  local clsag = true
  local bulletproof_plus = true
  local use_view_tags = true
  local base_fee = tools.wallet:get_base_fee(PRIORITY)
  local fee_quantization_mask = tools.wallet:get_fee_quantization_mask()

  local fee = tools.wallet:estimate_fee(
    use_per_byte_fee, use_rct, n_inputs, mixin, n_outputs, extra_size,
    bulletproof, clsag, bulletproof_plus, use_view_tags,
    base_fee, fee_quantization_mask)

  print("fee: ", fee:print_money())

  return fee
end

function atomic_swap:creator_transfer_locked_coin_to_shared()

  local ok, bc_height, err = tools.wallet:get_daemon_blockchain_height()
  if not ok then
    print("creator_transfer_locked_coin_to_shared error get daemon height", err)
    return
  end

  local extra = cryptonote.tx_extra_data.new()
  extra:set_hash_x(self.CSender.HX, bc_height + AST_T1) -- unlock_time,
  extra:set_pubkey_x(self.CSender.Ax_pub)
  extra:set_pubkey_t(self.CSender.Ct_pub)

  local fee = self:calculate_reserved_fee_for_shared()
  local amount = self.CSender.amount + fee
  local to_addr = self._shared:get_address()

  local ok, pptx, signers, err = tools.wallet:create_transaction(
    to_addr, -- account_public_address
    false, -- is_subaddress
    amount,
    1, -- MIXIN_COUNT
    ATOMIC_SWAP_HASH_X_UNLOCK_TIME, -- unlock_time,
    extra,
    "", -- extra_nonce,
    PRIORITY,
    0, -- subaddr_account,
    {} -- subaddr_indices_array,
  )

  if ok then
    for _,ptx in ipairs(pptx) do
      tools.wallet:commit_tx(ptx)

      local s_to_addr = cryptonote.get_account_address_as_str(to_addr, false)
      self._event = "3. Creator send locked transfer to shared address ["..s_to_addr.."] ..."

      print(self._event);
      print("commit txid: ", ptx.tx.txid);
      print("amount=", amount:print_money())
      --print("hex: ", ptx.tx:to_hex());
      --print("unlock_time: ", ptx.tx.unlock_time)
      --print("extra: ", ptx.tx.extra)
      --print("json: ", ptx.tx);

      self._zyre:creator_wait_transfer_locked_coin_on_shared()
    end
  else
    print("Error creator_transfer_locked_coin_to_shared: "..err)
  end

end

function atomic_swap:creator_wait_transfer_locked_coin_on_shared()

  print("creator_wait_transfer_locked_coin_on_shared ...")

  local root = self

  local refresh_n = 0
  -- check transaction
  timeout(SHARED_TIMEOUT_REFRESH, function()
  
    local loop = refresh_n < SHARED_WAIT_TIMES or false
    refresh_n = refresh_n + 1
  
    print("shared refresh ...")
    root._shared:refresh()
  
    for _, td in ipairs(root._shared:get_transfers()) do
  
      local extra = td.tx.extra
      local height = td.height
      local txid = td.txid
      local amount = td.amount
      local xx, HX, unlock_time = extra:get_hash_x()
      local px, Cx_pub = extra:get_pubkey_x()
      local pt, At_pub = extra:get_pubkey_t()
  
      if td.tx.unlock_time == ATOMIC_SWAP_HASH_X_UNLOCK_TIME  and
         root.CReceiver.amount < amount                       and
         xx and root.CReceiver.HX     == HX                   and
         px and root.CReceiver.Cx_pub == Cx_pub               and
         pt and height + AST_T2 == unlock_time
  
      then
  
        print("height:      ", height)
        print("txid:        ", txid)
        print("amount:      ", amount:print_money())
        print("unlock_time: ", unlock_time)
        print("HX:          ", HX)
        print("Cx_pub:      ", Cx_pub)
  
        print("Received locked transfer")

        local wait_for_height = height + BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW

        timeout(SHARED_TIMEOUT_REFRESH, function()

          local ok, height, err = tools.wallet:get_daemon_blockchain_height()
          if not ok then
            print("get_daemon_blockchain_height error: ", err)
            return false
          end

          print("height: "..tostring(height)..", wait for ... "..tostring(wait_for_height))

          if height > wait_for_height then
            root._shared:refresh()
            root:creator_transfer_locked_coin_from_shared()
            return false
          end

          return true;
        end)
  
        loop = false
  
      else
  
        print("tx.height:      ", height)
        print("tx.txid:        ", txid)
        print("tx.amount:      ", amount:print_money()  ,  ", expect: ",   root.CReceiver.amount:print_money() )
        print("tx.unlock_time: ", unlock_time           ,  ", expect: ",   height + AST_T2                     )
        print("         types: ", type(unlock_time)     ,  ",         ",   type(height + AST_T2)               )
        print("tx.HX:          ", HX                    ,  ", expect: ",   root.CReceiver.HX                   )
        print("tx.Cx_pub:      ", Cx_pub                ,  ", expect: ",   root.CReceiver.Cx_pub               )
        print("tx.At_pub:      ", At_pub                ,  ", expect: ",   root.CReceiver.At_pub               )
  
      end
  
    end
  
    return loop
  end)
end

function atomic_swap:creator_transfer_locked_coin_from_shared()

  print("creator_transfer_locked_coin_from_shared ...")

  local root = self

  local sign = crypto.generate_signature(self.CReceiver.HX, self.CReceiver.Cx_pub, self.CReceiver.Cx_sec)
  local extra = cryptonote.tx_extra_data.new()
  extra:set_x(self.CReceiver.X)
  extra:set_sign_x(sign)
  local to_addr = tools.wallet:get_address()

  local ok, pptx, signers, err = root._shared:create_transaction(
    to_addr, -- account_public_address
    false, -- is_subaddress
    self.CReceiver.amount,
    1, -- fake_outs is 0, MIXIN_COUNT = 1,
    tools.uint64_t(0), -- unlock_time,
    extra,
    "", -- extra_nonce,
    PRIORITY,
    0, -- subaddr_account,
    {} -- subaddr_indices_array,
  )

  if ok then
    if #pptx == 0 then
      print("no results");
    end
    for _,ptx in ipairs(pptx) do
      root._shared:commit_tx(ptx)

      local s_to_addr = cryptonote.get_account_address_as_str(to_addr, false)
      self._event = "4. Creator send locked transfer from shared to self address ["..s_to_addr.."] ..."

      print(self._event);
      print("commit txid: ", ptx.tx.txid);
      print("balance: ", root._shared:balance_all(false):print_money())
    end
  else
    print("Error creator_transfer_locked_coin_to_shared: "..err)
  end

end

function atomic_swap:acceptor_transfer_locked_coin_to_shared()

  local root = self

  local ok, bc_height, err = tools.wallet:get_daemon_blockchain_height()
  if not ok then
    print("creator_transfer_locked_coin_to_shared error get daemon height", err)
    return
  end

  local extra = cryptonote.tx_extra_data.new()
  extra:set_hash_x(root.ASender.HX, bc_height + AST_T2) -- unlock_time,
  extra:set_pubkey_x(root.ASender.Cx_pub)
  extra:set_pubkey_t(root.ASender.At_pub)

  local fee = root:calculate_reserved_fee_for_shared()
  local amount = root.ASender.amount + fee
  local to_addr = root._shared:get_address()

  local ok, pptx, signers, err = tools.wallet:create_transaction(
    to_addr, -- account_public_address
    false, -- is_subaddress
    amount,
    1, -- MIXIN_COUNT
    ATOMIC_SWAP_HASH_X_UNLOCK_TIME, -- unlock_time,
    extra,
    "", -- extra_nonce,
    PRIORITY,
    0, -- subaddr_account,
    {} -- subaddr_indices_array,
  )

  if ok then
    for _,ptx in ipairs(pptx) do
      tools.wallet:commit_tx(ptx)

      local s_to_addr = cryptonote.get_account_address_as_str(to_addr, false)
      root._event = "2. Send locked transfer to shared address ["..s_to_addr.."] ..."

      print(root._event)
      print("commit txid: ", ptx.tx.txid);
      print("amount=", amount:print_money())
      --print("hex: ", ptx.tx:to_hex());
      --print("unlock_time: ", ptx.tx.unlock_time)
      --print("extra: ", ptx.tx.extra)
      --print("json: ", ptx.tx);
    end
  else
    print("Error acceptor_transfer_locked_coin_to_shared: "..err)
  end
end

function atomic_swap:acceptor_transfer_locked_coin_from_shared(X)

  print("acceptor_transfer_locked_coin_from_shared ...")

  local root = self

  root.AReceiver.X = X
  local HX = crypto.cn_fast_hash(X)

  if root.AReceiver.HX ~= HX then
    print("Failed hash of X: "..epee.to_hex(X).."\n   hash(X): "..HX.."\n   not eq of HX: "..root.AReceiver.HX)
    return
  end

  local sign = crypto.generate_signature(root.AReceiver.HX, root.AReceiver.Ax_pub, root.AReceiver.Ax_sec)
  local extra = cryptonote.tx_extra_data.new()
  extra:set_x(X)
  extra:set_sign_x(sign)
  local to_addr = tools.wallet:get_address()

  local ok, pptx, signers, err = root._shared:create_transaction(
    to_addr, -- account_public_address
    false, -- is_subaddress
    root.AReceiver.amount,
    1, -- fake_outs is 0, MIXIN_COUNT = 1,
    tools.uint64_t(0), -- unlock_time,
    extra,
    "", -- extra_nonce,
    PRIORITY,
    0, -- subaddr_account,
    {} -- subaddr_indices_array,
  )

  if ok then
    if #pptx == 0 then
      print("no results");
    end
    for _,ptx in ipairs(pptx) do
      root._shared:commit_tx(ptx)

      local s_to_addr = cryptonote.get_account_address_as_str(to_addr, false)
      root._event = "5. Acceptor send locked transfer from shared to self address ["..s_to_addr.."] ..."

      print(root._event);
      print("commit txid: ", ptx.tx.txid);
      print("balance: ", root._shared:balance_all(false):print_money())
    end
  else
    print("Error creator_transfer_locked_coin_to_shared: "..err)
  end

end

return function(_zyre)
  if not atomic_swap._zyre then
    atomic_swap:init(_zyre)
  end
  return atomic_swap
end