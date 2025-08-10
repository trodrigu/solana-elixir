defmodule Solana.AddressTableHelper do
  @moduledoc """
  Helper for building address table lookups for Solana v0 transactions.
  Accepts base58 or binary pubkeys for lookup table addresses and contained addresses.
  """

  alias Solana.Transaction.AddressTableLookup

  @type account :: %{key: binary(), writable?: boolean()}
  @type lookup_table :: %{address: binary() | String.t(), addresses: [binary() | String.t()]}
  @type address_lookup_table_account :: %{
    key: binary(),
    addresses: [binary()],
    authority: binary() | nil,
    deactivation_slot: non_neg_integer() | nil
  }

  @doc """
  Fetches multiple address lookup table accounts from the network.
  Similar to JavaScript's getMultipleAccountsInfo pattern.
  """
  @spec get_address_lookup_table_accounts([binary() | String.t()], String.t()) :: 
    {:ok, [address_lookup_table_account()]} | {:error, term()}
  def get_address_lookup_table_accounts(keys, rpc_url) do
    pubkeys = Enum.map(keys, &decode_pubkey/1)
    req = Solana.RPC.Request.get_multiple_accounts(pubkeys, encoding: "base64")
    
    case rpc_client().send(rpc_url, req) do
      {:ok, %{body: %{"result" => %{"value" => account_infos}}}} ->
        accounts = 
          account_infos
          |> Enum.with_index()
          |> Enum.filter(fn {account_info, _idx} -> account_info != nil end)
          |> Enum.map(fn {account_info, idx} ->
            key = Enum.at(pubkeys, idx)
            %{"data" => [b64_data, "base64"]} = account_info
            data = Base.decode64!(b64_data)
            
            %{
              key: B58.encode58(key),
              state: %{
                addresses: parse_lookup_table_addresses(data),
                authority: parse_lookup_table_authority(data),
                deactivation_slot: parse_lookup_table_deactivation_slot(data),
                # TODO: 
                #last_extended_slot: parse_last_extended_slot(data),
                #last_extended_slot_start_index: parse_last_extended_slot(data) 
              }
            }
          end)
        {:ok, accounts}
      
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_response}
    end
  end

  @doc """
  Fetches a single address lookup table account.
  """
  @spec get_address_lookup_table_account(binary() | String.t(), String.t()) :: 
    {:ok, address_lookup_table_account()} | {:error, term()}
  def get_address_lookup_table_account(key, rpc_url) do
    case get_address_lookup_table_accounts([key], rpc_url) do
      {:ok, [account]} -> {:ok, account}
      {:ok, []} -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Builds address table lookups from accounts and fetched lookup table data.
  """
  @spec build_address_table_lookups_from_network([account()], [binary() | String.t()], String.t()) :: 
    {:ok, [AddressTableLookup.t()]} | {:error, term()}
  def build_address_table_lookups_from_network(accounts, lookup_table_keys, rpc_url) do
    case get_address_lookup_table_accounts(lookup_table_keys, rpc_url) do
      {:ok, lookup_table_accounts} ->
        lookups = Enum.map(lookup_table_accounts, fn table_account ->
          {writable, readonly} = categorize_account_indexes(accounts, table_account.addresses)
          
          %AddressTableLookup{
            account_key: table_account.key,
            writable_indexes: writable,
            readonly_indexes: readonly
          }
        end)
        {:ok, lookups}
      
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Given a list of accounts and lookup tables, returns a list of AddressTableLookup structs.
  Accounts and lookup table addresses can be base58 strings or binaries.
  """
  @spec build_address_table_lookups([account()], [lookup_table()]) :: [AddressTableLookup.t()]
  def build_address_table_lookups(accounts, lookup_tables) do
    Enum.map(lookup_tables, fn %{address: table_key, addresses: table_accounts} ->
      table_key_bin = decode_pubkey(table_key)
      table_accounts_bin = Enum.map(table_accounts, &decode_pubkey/1)

      {writable, readonly} = categorize_account_indexes(accounts, table_accounts_bin)

      %AddressTableLookup{
        account_key: table_key_bin,
        writable_indexes: writable,
        readonly_indexes: readonly
      }
    end)
  end

  # Private functions

  defp categorize_account_indexes(accounts, table_accounts_bin) do
    accounts
    |> Enum.reduce({[], []}, fn %{key: key, writable?: writable?}, {w_acc, r_acc} ->
      key_bin = decode_pubkey(key)
      case Enum.find_index(table_accounts_bin, &(&1 == key_bin)) do
        nil -> {w_acc, r_acc}
        idx when writable? -> {w_acc ++ [idx], r_acc}
        idx -> {w_acc, r_acc ++ [idx]}
      end
    end)
  end

  defp parse_lookup_table_addresses(data) do
    # Skip metadata (56 bytes) and parse addresses
    <<_meta::binary-size(56), rest::binary>> = data
    for <<key::binary-size(32) <- rest>>, do: B58.encode58(key)
  end

  defp parse_lookup_table_authority(data) do
    # Authority is at offset 8-40 in the metadata
    <<_::binary-size(8), authority::binary-size(32), _::binary>> = data
    # Check if authority is all zeros (null)
    if authority == <<0::256>>, do: nil, else: B58.encode58(authority)
  end

  defp parse_lookup_table_deactivation_slot(data) do
    # Deactivation slot is at offset 40-48 in the metadata
    <<_::binary-size(40), slot::little-unsigned-64, _::binary>> = data
    # Check if deactivation slot is max value (not deactivated)
    if slot == 0xFFFFFFFFFFFFFFFF, do: nil, else: slot
  end

  defp decode_pubkey(<<_::256>> = bin), do: bin
  defp decode_pubkey(str) when is_binary(str) do
    case Solana.pubkey(str) do
      {:ok, bin} -> bin
      _ -> raise ArgumentError, "invalid pubkey: #{str}"
    end
  end

  defp rpc_client do
    Application.get_env(:solana, :rpc_client, Solana.RPC)
  end

end 
