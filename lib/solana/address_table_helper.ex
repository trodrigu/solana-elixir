defmodule Solana.AddressTableHelper do
  @moduledoc """
  Helper for building address table lookups for Solana v0 transactions.
  Accepts base58 or binary pubkeys for lookup table addresses and contained addresses.
  """

  alias Solana.Transaction.AddressTableLookup

  @type account :: %{key: binary(), writable?: boolean()}
  @type lookup_table :: %{address: binary() | String.t(), addresses: [binary() | String.t()]}

  @doc """
  Given a list of accounts and lookup tables, returns a list of AddressTableLookup structs.
  Accounts and lookup table addresses can be base58 strings or binaries.
  """
  @spec build_address_table_lookups([account()], [lookup_table()]) :: [AddressTableLookup.t()]
  def build_address_table_lookups(accounts, lookup_tables) do
    Enum.map(lookup_tables, fn %{address: table_key, addresses: table_accounts} ->
      table_key_bin = decode_pubkey(table_key)
      table_accounts_bin = Enum.map(table_accounts, &decode_pubkey/1)

      {writable, readonly} =
        accounts
        |> Enum.reduce({[], []}, fn %{key: key, writable?: writable?}, {w_acc, r_acc} ->
          key_bin = decode_pubkey(key)
          case Enum.find_index(table_accounts_bin, &(&1 == key_bin)) do
            nil -> {w_acc, r_acc}
            idx when writable? -> {w_acc ++ [idx], r_acc}
            idx -> {w_acc, r_acc ++ [idx]}
          end
        end)

      %AddressTableLookup{
        account_key: table_key_bin,
        writable_indexes: writable,
        readonly_indexes: readonly
      }
    end)
  end

  defp decode_pubkey(<<_::256>> = bin), do: bin
  defp decode_pubkey(str) when is_binary(str), do: B58.decode58(str)
end 