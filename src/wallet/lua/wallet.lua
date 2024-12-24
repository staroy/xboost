local wallet_name = tools.wallet:get_wallet_name()

_zyre = zyre(wallet_name, tools.wallet:get_attribute("zyre-pin") or "123")
_zyre:join("xboost-public-"..wallet_name)

local atomic_swap = require("atomic_swap")(_zyre)

function tools.wallet:on_message_chat_received(height, txid, mtype, freq, chat, n, sender, data, description, short_name, enable_comments, timestamp, parent)
  atomic_swap:on_message_chat_received(height, txid, mtype, freq, chat, n, sender, data, description, short_name, enable_comments, timestamp, parent)
end

print("atomic swap inited")