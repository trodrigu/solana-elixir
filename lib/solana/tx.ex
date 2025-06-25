defmodule Solana.Transaction do
  @moduledoc """
  Functions for building and encoding Solana
  [transactions](https://docs.solana.com/developing/programming-model/transactions)
  """
  require Logger
  alias Solana.{Account, CompactArray, Instruction}

  defmodule AddressTableLookup do
    @moduledoc """
    Represents an address table lookup for versioned Solana transactions.
    - account_key: The address lookup table account public key.
    - writable_indexes: List of indexes into the lookup table for writable accounts.
    - readonly_indexes: List of indexes into the lookup table for readonly accounts.
    """
    defstruct [
      :account_key,
      writable_indexes: [],
      readonly_indexes: []
    ]
  end

  @typedoc """
  All the details needed to encode a transaction.
  - version: Transaction version (0 = legacy, 1 = v0 versioned, etc.)
  - address_table_lookups: List of address table lookups for versioned transactions.
  """
  @type address_table_lookup :: %AddressTableLookup{
          account_key: Solana.key(),
          writable_indexes: [non_neg_integer()],
          readonly_indexes: [non_neg_integer()]
        }

  @type t :: %__MODULE__{
          payer: Solana.key() | nil,
          blockhash: binary | nil,
          instructions: [Instruction.t()],
          signers: [Solana.keypair()],
          version: non_neg_integer(),
          address_table_lookups: [address_table_lookup()]
        }

  @typedoc """
  The possible errors encountered when encoding a transaction.
  """
  @type encoding_err ::
          :no_payer
          | :no_blockhash
          | :no_program
          | :no_instructions
          | :mismatched_signers

  defstruct [
    :payer,
    :blockhash,
    instructions: [],
    signers: [],
    version: 0,
    address_table_lookups: []
  ]

  @doc """
  decodes a base58-encoded signature and returns it in a tuple.

  If it fails, return an error tuple.
  """
  @spec decode(encoded :: binary) :: {:ok, binary} | {:error, binary}
  def decode(encoded) when is_binary(encoded) do
    case B58.decode58(encoded) do
      {:ok, decoded} -> check(decoded)
      _ -> {:error, "invalid signature"}
    end
  end

  def decode(_), do: {:error, "invalid signature"}

  @doc """
  decodes a base58-encoded signature and returns it.

  Throws an `ArgumentError` if it fails.
  """
  @spec decode!(encoded :: binary) :: binary
  def decode!(encoded) when is_binary(encoded) do
    case decode(encoded) do
      {:ok, key} ->
        key

      {:error, _} ->
        raise ArgumentError, "invalid signature input: #{encoded}"
    end
  end

  @doc """
  Checks to see if a transaction's signature is valid.

  Returns `{:ok, signature}` if it is, and an error tuple if it isn't.
  """
  @spec check(binary) :: {:ok, binary} | {:error, :invalid_signature}
  def check(signature)
  def check(<<signature::binary-64>>), do: {:ok, signature}
  def check(_), do: {:error, :invalid_signature}

  @doc """
  Encodes a `t:Solana.Transaction.t/0` into a [binary
  format](https://docs.solana.com/developing/programming-model/transactions#anatomy-of-a-transaction)

  Returns `{:ok, encoded_transaction}` if the transaction was successfully
  encoded, or an error tuple if the encoding failed -- plus more error details
  via `Logger.error/1`.
  """
  @spec to_binary(tx :: t) :: {:ok, binary()} | {:error, encoding_err()}
  def to_binary(%__MODULE__{version: 0} = tx), do: to_binary_legacy(tx)
  def to_binary(%__MODULE__{version: 1, address_table_lookups: lookups} = tx) do
    with {:ok, ixs} <- check_instructions(List.flatten(tx.instructions)),
         accounts = compile_accounts(ixs, tx.payer),
         true <- signers_match?(accounts, tx.signers) do
      message = encode_message_v0(accounts, tx.blockhash, ixs, lookups)
      signatures =
        tx.signers
        |> reorder_signers(accounts)
        |> Enum.map(&sign(&1, message))
        |> CompactArray.to_iolist()
      {:ok, :erlang.list_to_binary([[0x80], signatures, message])}
    else
      {:error, :no_program, idx} ->
        Logger.error("Missing program id on instruction at index #{idx}")
        {:error, :no_program}
      {:error, message, idx} ->
        Logger.error("error compiling instruction at index #{idx}: #{inspect(message)}")
        {:error, message}
      false ->
        {:error, :mismatched_signers}
    end
  end

  def check_instructions(ixs) do
    ixs
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, ixs}, fn
      {{:error, message}, idx}, _ -> {:halt, {:error, message, idx}}
      {%{program: nil}, idx}, _ -> {:halt, {:error, :no_program, idx}}
      _, acc -> {:cont, acc}
    end)
  end

  # https://docs.solana.com/developing/programming-model/transactions#account-addresses-format
  defp compile_accounts(ixs, payer) do
    ixs
    |> Enum.map(fn ix -> [%Account{key: ix.program} | ix.accounts] end)
    |> List.flatten()
    |> Enum.reject(&(&1.key == payer))
    |> Enum.sort_by(&{&1.signer?, &1.writable?}, &>=/2)
    |> Enum.uniq_by(& &1.key)
    |> cons(%Account{writable?: true, signer?: true, key: payer})
  end

  defp cons(list, item), do: [item | list]

  defp signers_match?(accounts, signers) do
    expected = MapSet.new(Enum.map(signers, &elem(&1, 1)))

    accounts
    |> Enum.filter(& &1.signer?)
    |> Enum.map(& &1.key)
    |> MapSet.new()
    |> MapSet.equal?(expected)
  end

  # https://docs.solana.com/developing/programming-model/transactions#message-format
  defp encode_message_v0(accounts, blockhash, ixs, lookups) do
    [
      create_header(accounts),
      CompactArray.to_iolist(Enum.map(accounts, & &1.key)),
      blockhash |> :erlang.binary_to_list(),
      encode_address_table_lookups(lookups),
      CompactArray.to_iolist(encode_instructions(ixs, accounts))
    ]
    |> :erlang.list_to_binary()
  end

  defp encode_address_table_lookups([]), do: CompactArray.to_iolist([])
  defp encode_address_table_lookups(lookups) do
    [CompactArray.encode_length(length(lookups)) |
      Enum.flat_map(lookups, fn %AddressTableLookup{account_key: key, writable_indexes: w, readonly_indexes: r} ->
        [key, CompactArray.to_iolist(w), CompactArray.to_iolist(r)]
      end)
    ]
  end

  # https://docs.solana.com/developing/programming-model/transactions#message-header-format
  defp create_header(accounts) do
    accounts
    |> Enum.reduce(
      {0, 0, 0},
      &{
        unary(&1.signer?) + elem(&2, 0),
        unary(&1.signer? && !&1.writable?) + elem(&2, 1),
        unary(!&1.signer? && !&1.writable?) + elem(&2, 2)
      }
    )
    |> Tuple.to_list()
  end

  defp unary(result?), do: if(result?, do: 1, else: 0)

  # https://docs.solana.com/developing/programming-model/transactions#instruction-format
  defp encode_instructions(ixs, accounts) do
    idxs = index_accounts(accounts)

    Enum.map(ixs, fn ix = %Instruction{} ->
      [
        Map.get(idxs, ix.program),
        CompactArray.to_iolist(Enum.map(ix.accounts, &Map.get(idxs, &1.key))),
        CompactArray.to_iolist(ix.data)
      ]
    end)
  end

  defp reorder_signers(signers, accounts) do
    account_idxs = index_accounts(accounts)
    Enum.sort_by(signers, &Map.get(account_idxs, elem(&1, 1)))
  end

  defp index_accounts(accounts) do
    Enum.into(Enum.with_index(accounts, &{&1.key, &2}), %{})
  end

  defp sign({secret, pk}, message), do: Ed25519.signature(message, secret, pk)

  @doc """
  Parses a `t:Solana.Transaction.t/0` from data encoded in Solana's [binary
  format](https://docs.solana.com/developing/programming-model/transactions#anatomy-of-a-transaction)

  Returns `{transaction, extras}` if the transaction was successfully
  parsed, or `:error` if the provided binary could not be parsed. `extras`
  is a keyword list containing information about the encoded transaction,
  namely:

  - `:header` - the [transaction message
  header](https://docs.solana.com/developing/programming-model/transactions#message-header-format)
  - `:accounts` - an [ordered array of
  accounts](https://docs.solana.com/developing/programming-model/transactions#account-addresses-format)
  - `:signatures` - a [list of signed copies of the transaction
  message](https://docs.solana.com/developing/programming-model/transactions#signatures)
  """
  @spec parse(encoded :: binary) :: {t(), keyword} | :error
  def parse(<<0x80, rest::binary>>) do
    # v0 versioned transaction
    with {signatures, message, _} <- CompactArray.decode_and_split(rest, 64),
         <<header::binary-size(3), contents::binary>> <- message,
         {account_keys, contents, _key_count} <- CompactArray.decode_and_split(contents, 32),
         <<blockhash::binary-size(32), contents::binary>> <- contents,
         {lookups, contents} <- parse_address_table_lookups(contents),
         {:ok, raw_instructions} <- extract_instructions(contents) do
      # Build full account list: static + lookup table keys
      lookup_keys = Enum.flat_map(lookups, fn l ->
        Enum.map(l.writable_indexes ++ l.readonly_indexes, fn _ -> nil end)
      end)
      # For now, we don't have the actual lookup table keys, so we only use static keys
      # In a real implementation, you would fetch the lookup table accounts and insert their keys here
      full_accounts = account_keys ++ lookup_keys
      _indices = Enum.into(Enum.with_index(full_accounts, &{&2, &1}), %{})

      # Resolve instructions
      instructions = Enum.map(raw_instructions, fn {program_idx, account_indices, data} ->
        %Instruction{
          data: if(data == "", do: nil, else: :binary.list_to_bin(data)),
          program: Enum.at(full_accounts, program_idx),
          accounts: Enum.map(account_indices, &%Account{key: Enum.at(full_accounts, &1)})
        }
      end)

      {
        %__MODULE__{
          payer: account_keys |> List.first(),
          blockhash: blockhash,
          instructions: instructions,
          version: 1,
          address_table_lookups: lookups
        },
        [
          accounts: full_accounts,
          header: header,
          signatures: signatures,
          address_table_lookups: lookups
        ]
      }
    else
      _ -> :error
    end
  end
  def parse(encoded), do: parse_legacy(encoded)

  defp parse_address_table_lookups(data) do
    case CompactArray.decode_and_split(data) do
      {<<>>, 0} -> {[], <<>>}
      {raw, count} ->
        parse_address_table_lookups(raw, count, [])
    end
  end
  defp parse_address_table_lookups(data, 0, acc), do: {Enum.reverse(acc), data}
  defp parse_address_table_lookups(<<key::binary-size(32), rest::binary>>, n, acc) do
    {writable, rest, _} = CompactArray.decode_and_split(rest, 1)
    {readonly, rest, _} = CompactArray.decode_and_split(rest, 1)
    lookup = %AddressTableLookup{
      account_key: key,
      writable_indexes: Enum.map(writable, &:binary.decode_unsigned/1),
      readonly_indexes: Enum.map(readonly, &:binary.decode_unsigned/1)
    }
    parse_address_table_lookups(rest, n - 1, [lookup | acc])
  end

  defp extract_instructions(data) do
    with {ix_data, ix_count} <- CompactArray.decode_and_split(data),
         {reversed_ixs, ""} <- extract_instructions(ix_data, ix_count) do
      {:ok, Enum.reverse(reversed_ixs)}
    else
      error -> error
    end
  end

  defp extract_instructions(data, count) do
    Enum.reduce_while(1..count, {[], data}, fn _, {acc, raw} ->
      case extract_instruction(raw) do
        {ix, rest} -> {:cont, {[ix | acc], rest}}
        _ -> {:halt, :error}
      end
    end)
  end

  defp extract_instruction(raw) do
    with <<program::8, rest::binary>> <- raw,
         {accounts, rest, _} <- CompactArray.decode_and_split(rest, 1),
         {data, rest, _} <- extract_instruction_data(rest) do
      {{program, Enum.map(accounts, &:binary.decode_unsigned/1), data}, rest}
    else
      _ -> :error
    end
  end

  defp extract_instruction_data(""), do: {"", "", 0}
  defp extract_instruction_data(raw), do: CompactArray.decode_and_split(raw, 1)

  defp derive_accounts(keys, total, header) do
    <<signers_count::8, signers_readonly_count::8, nonsigners_readonly_count::8>> = header
    {signers, nonsigners} = Enum.split(keys, signers_count)
    {signers_write, signers_read} = Enum.split(signers, signers_count - signers_readonly_count)

    {nonsigners_write, nonsigners_read} =
      Enum.split(nonsigners, total - signers_count - nonsigners_readonly_count)

    List.flatten([
      Enum.map(signers_write, &%Account{key: &1, writable?: true, signer?: true}),
      Enum.map(signers_read, &%Account{key: &1, signer?: true}),
      Enum.map(nonsigners_write, &%Account{key: &1, writable?: true}),
      Enum.map(nonsigners_read, &%Account{key: &1})
    ])
  end

  defp to_binary_legacy(%__MODULE__{payer: nil}), do: {:error, :no_payer}
  defp to_binary_legacy(%__MODULE__{blockhash: nil}), do: {:error, :no_blockhash}
  defp to_binary_legacy(%__MODULE__{instructions: []}), do: {:error, :no_instructions}

  defp to_binary_legacy(tx = %__MODULE__{instructions: ixs, signers: signers}) do
    with {:ok, ixs} <- check_instructions(List.flatten(ixs)),
         accounts = compile_accounts(ixs, tx.payer),
         true <- signers_match?(accounts, signers) do
      message = encode_message_legacy(accounts, tx.blockhash, ixs)

      signatures =
        signers
        |> reorder_signers(accounts)
        |> Enum.map(&sign(&1, message))
        |> CompactArray.to_iolist()

      {:ok, :erlang.list_to_binary([signatures, message])}
    else
      {:error, :no_program, idx} ->
        Logger.error("Missing program id on instruction at index #{idx}")
        {:error, :no_program}

      {:error, message, idx} ->
        Logger.error("error compiling instruction at index #{idx}: #{inspect(message)}")
        {:error, message}

      false ->
        {:error, :mismatched_signers}
    end
  end

  defp encode_message_legacy(accounts, blockhash, ixs) do
    [
      create_header(accounts),
      CompactArray.to_iolist(Enum.map(accounts, & &1.key)),
      blockhash |> :erlang.binary_to_list(),
      CompactArray.to_iolist(encode_instructions(ixs, accounts))
    ]
    |> :erlang.list_to_binary()
  end

  defp parse_legacy(encoded) do
    with {signatures, message, _} <- CompactArray.decode_and_split(encoded, 64),
         <<header::binary-size(3), contents::binary>> <- message,
         {account_keys, hash_and_ixs, key_count} <- CompactArray.decode_and_split(contents, 32),
         <<blockhash::binary-size(32), ix_data::binary>> <- hash_and_ixs,
         {:ok, instructions} <- extract_instructions(ix_data) do
      tx_accounts = derive_accounts(account_keys, key_count, header)
      indices = Enum.into(Enum.with_index(tx_accounts, &{&2, &1}), %{})

      {
        %__MODULE__{
          payer: tx_accounts |> List.first() |> Map.get(:key),
          blockhash: blockhash,
          instructions:
            Enum.map(instructions, fn {program, accounts, data} ->
              %Instruction{
                data: if(data == "", do: nil, else: :binary.list_to_bin(data)),
                program: Map.get(indices, program) |> Map.get(:key),
                accounts: Enum.map(accounts, &Map.get(indices, &1))
              }
            end)
        },
        [
          accounts: tx_accounts,
          header: header,
          signatures: signatures
        ]
      }
    else
      _ -> :error
    end
  end

  @doc """
  Parses a versioned transaction and resolves address lookup table keys from the network.
  Accepts:
    - encoded: the transaction binary
    - rpc_url: the Solana RPC endpoint
    - fetch_fun: (optional) a function to fetch account info (defaults to Solana.RPC.send/2)
  Returns {transaction, extras} or :error
  """
  def parse_with_lookup(encoded, rpc_url, fetch_fun \\ &Solana.RPC.send/2) do
    case encoded do
      <<0x80, rest::binary>> ->
        with {signatures, message, _} <- CompactArray.decode_and_split(rest, 64),
             <<header::binary-size(3), contents::binary>> <- message,
             {account_keys, contents, _key_count} <- CompactArray.decode_and_split(contents, 32),
             <<blockhash::binary-size(32), contents::binary>> <- contents,
             {lookups, contents} <- parse_address_table_lookups(contents),
             {:ok, raw_instructions} <- extract_instructions(contents) do
          # Fetch and parse lookup table keys from the network
          lookup_keys = Enum.flat_map(lookups, fn lookup ->
            keys = fetch_lookup_table_keys(lookup.account_key, rpc_url, fetch_fun)
            Enum.map(lookup.writable_indexes ++ lookup.readonly_indexes, &Enum.at(keys, &1))
          end)
          full_accounts = account_keys ++ lookup_keys
          # Resolve instructions
          instructions = Enum.map(raw_instructions, fn {program_idx, account_indices, data} ->
            %Instruction{
              data: if(data == "", do: nil, else: :binary.list_to_bin(data)),
              program: Enum.at(full_accounts, program_idx),
              accounts: Enum.map(account_indices, &%Account{key: Enum.at(full_accounts, &1)})
            }
          end)
          {
            %__MODULE__{
              payer: account_keys |> List.first(),
              blockhash: blockhash,
              instructions: instructions,
              version: 1,
              address_table_lookups: lookups
            },
            [
              accounts: full_accounts,
              header: header,
              signatures: signatures,
              address_table_lookups: lookups
            ]
          }
        else
          _ -> :error
        end
      _ -> parse(encoded)
    end
  end

  defp fetch_lookup_table_keys(table_pubkey, rpc_url, fetch_fun) do
    req = Solana.RPC.Request.get_account_info(table_pubkey, encoding: "base64")
    case fetch_fun.(rpc_url, req) do
      {:ok, %{body: [%{"result" => %{"value" => %{"data" => [b64, "base64"]}}}]}} ->
        data = Base.decode64!(b64)
        parse_lookup_table_account_data(data)
      _ -> []
    end
  end

  defp parse_lookup_table_account_data(data) do
    # Address Lookup Table format:
    # 32 bytes: authority
    # 8 bytes: deactivation slot
    # 4 bytes: key count (little-endian)
    # N * 32 bytes: keys
    <<_authority::binary-size(32), _deact_slot::binary-size(8), key_count::little-32, rest::binary>> = data
    for <<key::binary-size(32) <- binary_part(rest, 0, key_count * 32)>>, do: key
  end
end
