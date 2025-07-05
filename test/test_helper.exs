ExUnit.start()

Mox.defmock(Solana.RPC.Mock, for: Solana.RPC)

Application.put_env(:solana, :rpc_client, Solana.RPC.Mock)
