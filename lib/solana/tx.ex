defmodule Solana.Transaction do
  @moduledoc """
  Functions for building and encoding Solana
  [transactions](https://docs.solana.com/developing/programming-model/transactions)
  """
  require Logger
  alias Solana.{Account, CompactArray, Instruction}
  alias Solana.KeyMeta

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

  defmodule CompiledKeys do
    @moduledoc """
    Holds the compiled key information for v0 transactions.
    """
    defstruct [
      :payer,
      :static_accounts,
      :account_lookup_map
    ]
  end

  defmodule MessageHeader do
    defstruct num_required_signatures: 0,
              num_readonly_signed_accounts: 0,
              num_readonly_unsigned_accounts: 0
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
    case decode58!(encoded) do
      decoded -> check(decoded)
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

  def to_binary(%__MODULE__{version: 1, address_table_lookups: lookup_table_accounts} = tx) do
    with {:ok, ixs} <- check_instructions(List.flatten(tx.instructions)),
         dbg(Enum.count(ixs)),
         compiled_keys = compile_keys(ixs, tx.payer),
         {address_table_lookups, account_keys_from_lookups, updated_compiled_keys} =
           process_address_lookup_tables(lookup_table_accounts, compiled_keys),
         {header, static_account_keys} = get_message_components(updated_compiled_keys),
         # TODO: create key_segments from this and pass below!
         message_account_keys =
           build_message_account_keys(static_account_keys, account_keys_from_lookups),
         compiled_instructions = compile_instructions_v0(ixs, message_account_keys),
         true <- signers_match?(updated_compiled_keys, tx.signers) do
      # key_segments should have all static_account_keys and writable and readonly keys from lookups
      message =
        build_message_v0(
          header,
          static_account_keys,
          tx.blockhash,
          compiled_instructions,
          address_table_lookups
        )

      encoded_message = encode_message(message)

      signatures =
        tx.signers
        |> reorder_signers(updated_compiled_keys)
        |> Enum.map(&sign(&1, encoded_message))
        |> CompactArray.to_iolist()

      IO.puts("Hex dump: " <> Base.encode16(encoded_message, case: :lower))
      dbg(encoded_message, limit: :infinity)

      binary = :erlang.list_to_binary([signatures, encoded_message])
      {:ok, binary}
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

  def encode_message(message) do
    static_account_keys_binary =
      Enum.map(message.static_account_keys, fn key ->
        {:ok, binary} = B58.decode58(key)
        binary |> :erlang.binary_to_list()
      end)

    header = encode_message_v0_header(message.header) |> dbg()
    CompactArray.to_iolist(header) |> :erlang.list_to_binary() |> Base.encode16(case: :lower)

    [
      [0x80],
      header,
      CompactArray.to_iolist(static_account_keys_binary),
      message.blockhash |> :erlang.binary_to_list(),
      encode_instructions(message.compiled_instructions),
      encode_address_table_lookups(message.address_table_lookups)
    ]
    |> :erlang.list_to_binary()
    |> dbg(limit: :infinity)
  end

  defp encode_message_v0_header(header) do
    [
      header.num_required_signatures,
      header.num_readonly_signed_accounts,
      header.num_readonly_unsigned_accounts
    ]
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

  defp signers_match?(compiled_keys, signers) do
    expected =
      signers
      |> Enum.map(&elem(&1, 1))
      |> Enum.map(&B58.encode58/1)
      |> MapSet.new()

    compiled_keys.key_meta
    |> Enum.filter(fn %{address: _, key_meta: v} -> v.signer? end)
    |> Enum.map(fn %{address: k, key_meta: _} -> k end)
    |> MapSet.new()
    |> MapSet.equal?(expected)
  end

  defp encode_address_table_lookups(lookups) when length(lookups) == 0,
    do: CompactArray.to_iolist([])

  defp encode_address_table_lookups(lookups) do
    encoded_lookups = Enum.flat_map(lookups, fn %{
                                    address_table_lookup: %{
                                      account_key: account_key,
                                      writable_indexes: w,
                                      readonly_indexes: r
                                    }
                                  } ->
          dbg(account_key)
          [B58.decode58!(account_key) |> :erlang.binary_to_list(), CompactArray.to_iolist(w), CompactArray.to_iolist(r)]
        end)

    dbg(encoded_lookups)

    [
      CompactArray.encode_length(length(lookups))
      | encoded_lookups
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

  # https://docs.solana.com/developing/programming-model/transactions#message-header-format
  defp create_header(writable_signers, readonly_signers, readonly_non_signers) do
    %{
      num_required_signatures: Enum.count(writable_signers) + Enum.count(readonly_signers),
      num_readonly_signed_accounts: Enum.count(readonly_signers),
      num_readonly_unsigned_accounts: Enum.count(readonly_non_signers)
    }
  end

  defp unary(result?), do: if(result?, do: 1, else: 0)

  # https://docs.solana.com/developing/programming-model/transactions#instruction-format
  defp encode_instructions(ixs) do
    dbg(length(ixs))

    Enum.map(ixs, fn ix ->
      dbg(ix.account_indices,limit: :infinity)
      [
        length(ixs),
        ix.program_idx,
        CompactArray.to_iolist(ix.account_indices),
        CompactArray.to_iolist(ix.data)
      ]
    end)
  end

  defp reorder_signers(signers, accounts) do
    accounts = Enum.map(accounts.key_meta, & &1.key_meta)
    account_idxs = index_accounts(accounts)
    Enum.sort_by(signers, &Map.get(account_idxs, elem(&1, 1)))
  end

  defp index_accounts(accounts) do
    Enum.into(Enum.with_index(accounts, &{&1.key, &2}), %{})
  end

  defp sign({secret, pk}, message), do: Ed25519.signature(message, secret, pk)

  def compile_keys(instructions, payer) do
    get_or_insert_default = fn pubkey, key_meta_list ->
      address = B58.encode58(pubkey)

      if _key_meta = Enum.find(key_meta_list, & &1.address == address) do
        key_meta_list
      else
        key_meta_list ++
          [
            %{
              address: address,
              key_meta: %KeyMeta{
                key: address,
                signer?: false,
                writable?: false,
                invoked?: false
              }
            }
          ]
      end
    end

    with_payer_inserted =
      get_or_insert_default.(payer, [])

    with_payer_index =
      Enum.find_index(with_payer_inserted, & &1.address == B58.encode58(payer))

    key_meta_list =
      List.update_at(
        with_payer_inserted,
        with_payer_index,
        &%{&1 | address: &1.key_meta.key, key_meta: %KeyMeta{key: &1.key_meta.key, signer?: true, writable?: true, invoked?: &1.key_meta.invoked?}}
      )
      |> dbg()

    final_key_meta_list =
      for ix <- instructions, reduce: key_meta_list do
        k ->
          dbg(Enum.count(ix.accounts))

        with_program_inserted =
            get_or_insert_default.(ix.program, k)

        program_index = Enum.find_index(with_program_inserted, & &1.address == B58.encode58(ix.program))

        updated_key_meta_list =
          List.update_at(
            with_program_inserted,
            program_index,
            &%{&1 | address: &1.key_meta.key, key_meta: %KeyMeta{key: &1.key_meta.key, signer?: false, writable?: false, invoked?: true}}
          )

          for a <- ix.accounts, reduce: updated_key_meta_list do
            ki ->
              ki
              |> then(fn l ->
                if Enum.any?(l, & &1.address == B58.encode58(a.key)) do
                  l
                else
                  with_a_updated =
                    a.key
                    |> get_or_insert_default.(l)

                  a_index =
                    Enum.find_index(with_a_updated, & &1.address == B58.encode58(a.key))

                  List.update_at(
                    with_a_updated,
                    a_index,
                    &%{&1 | address: &1.key_meta.key, key_meta: %KeyMeta{key: &1.key_meta.key, signer?: a.signer?, writable?: a.writable?}}
                  )
                end
              end)
          end
      end

    %Solana.CompiledKeys{
      payer: payer,
      key_meta: final_key_meta_list |> dbg()
    }
  end

  def process_address_lookup_tables(lookup_table_accounts, compiled_keys) do
    dbg(lookup_table_accounts)
    {address_table_lookups, account_keys_from_lookups, updated_compiled_keys} =
      Enum.reduce(
        lookup_table_accounts,
        {[], %{writable: [], readonly: []}, compiled_keys},
        fn lookup_table,
           {acc_lookups, %{writable: writable, readonly: readonly}, compiled_keys} ->
          if table_lookup = extract_table_lookup(lookup_table, compiled_keys) do
            dbg(table_lookup)
            updated_lookups = [table_lookup | acc_lookups]

            updated_writable = writable ++ table_lookup.keys_from_lookup.writable
            updated_readonly = readonly ++ table_lookup.keys_from_lookup.readonly

            {updated_lookups, %{writable: updated_writable, readonly: updated_readonly},
             table_lookup.compiled_keys}
          end
        end)
        |> then(fn {address_table_lookups, account_keys_from_lookups, updated_compiled_keys} ->
          {
            Enum.reverse(address_table_lookups),
            %{
              writable: account_keys_from_lookups.writable,
              readonly: account_keys_from_lookups.readonly
            },
            updated_compiled_keys
          }
        end)

    {address_table_lookups, account_keys_from_lookups, updated_compiled_keys}
  end

  defp extract_table_lookup(lookup_table, compiled_keys) do
    writable_meta_filter = fn meta -> not meta.signer? && not meta.invoked? && meta.writable? end

    {writable_keys, writable_indexes, updated_compiled_keys} =
      get_keys_with_indexes(lookup_table, compiled_keys, writable_meta_filter) |> dbg()

    readonly_meta_filter = fn meta ->
      not meta.signer? && not meta.invoked? && not meta.writable?
    end

    {readonly_keys, readonly_indexes, updated_compiled_keys} =
      get_keys_with_indexes(lookup_table, updated_compiled_keys, readonly_meta_filter)

    %{
      address_table_lookup: %{
        account_key: lookup_table.key,
        writable_indexes: writable_indexes,
        readonly_indexes: readonly_indexes
      },
      keys_from_lookup: %{writable: writable_keys, readonly: readonly_keys},
      compiled_keys: updated_compiled_keys
    }
  end

  defp get_keys_with_indexes(lookup_table, compiled_keys, key_meta_filter) do
    filtered_keys =
      compiled_keys.key_meta
      |> Enum.filter(fn %{address: _key, key_meta: meta} ->
        key_meta_filter.(meta)
      end)
      |> Enum.map(& &1.address)

    addresses = lookup_table.state.addresses

    dbg(filtered_keys, label: "Filtered keys")

    {keys_with_indexes, indexes} =
      Enum.reduce(filtered_keys, {[], []}, fn k, {keys_with_indexes, indexes} ->
        if index = Enum.find_index(addresses, &(&1 == k)) do
          IO.puts("Pushing key #{k} at index #{index}")
          {[k | keys_with_indexes], [index | indexes]}|>dbg()
        else
          {keys_with_indexes, indexes}
        end
      end)
      |> then(fn {keys, indexes} ->
        {Enum.reverse(keys), Enum.reverse(indexes)}
      end)
      |> dbg()

    updated_key_meta = 
      compiled_keys.key_meta
      |> Enum.reject(fn meta -> meta.address in keys_with_indexes end)

    updated_compiled_keys = %{compiled_keys | key_meta: updated_key_meta}

    if Enum.any?(indexes, &(&1 > 256)),
      do: raise(ArgumentError, "Max lookup table index exceeded")

    {keys_with_indexes, indexes, updated_compiled_keys}
  end

  def get_message_components(compiled_keys) do
    dbg(Enum.count(compiled_keys.key_meta), label: "Total keys in compiled keys")

    writable_signers =
      compiled_keys.key_meta
      |> Enum.filter(fn %{address: _key, key_meta: meta} -> meta.signer? && meta.writable? end)
      |> Enum.map(fn %{address: key, key_meta: _meta} -> key end)
      |> dbg()

    readonly_signers =
      compiled_keys.key_meta
      |> Enum.filter(fn %{address: _key, key_meta: meta} -> meta.signer? && not meta.writable? end)
      |> Enum.map(fn %{address: key, key_meta: _meta} -> key end)

    writable_non_signers =
      compiled_keys.key_meta
      |> Enum.filter(fn %{address: _key, key_meta: meta} -> not meta.signer? && meta.writable? end)
      |> Enum.map(fn %{address: key, key_meta: _meta} -> key end)

    readonly_non_signers =
      compiled_keys.key_meta
      |> Enum.filter(fn %{address: _key, key_meta: meta} -> not meta.signer? && not meta.writable? end)
      |> Enum.map(fn %{address: key, key_meta: _meta} -> key end)

    header = create_header(writable_signers, readonly_signers, readonly_non_signers)

    dbg(header)

    static_account_keys =
      writable_signers ++ readonly_signers ++ writable_non_signers ++ readonly_non_signers

    {header, static_account_keys}
  end

  def build_message_account_keys(static_account_keys, account_keys_from_lookups) do
    %{
      static_account_keys: static_account_keys,
      account_keys_from_lookups: account_keys_from_lookups
    }
  end

  def compile_instructions_v0(instructions, message_account_keys) do
    dbg(message_account_keys)
    key_segments =
      (message_account_keys.static_account_keys ++
         message_account_keys.account_keys_from_lookups.writable ++
         message_account_keys.account_keys_from_lookups.readonly)
      |> dbg()

    Enum.map(instructions, fn ix ->
      dbg(ix.program)
      program_idx = Enum.find_index(key_segments, &(&1 == B58.encode58(ix.program)))
      dbg(program_idx)

      account_indices =
        Enum.map(ix.accounts, fn account ->
          Enum.find_index(key_segments, fn segment -> segment == B58.encode58(account.key) end)
        end)

      %{program_idx: program_idx, account_indices: account_indices, data: ix.data}
    end)
    |> dbg()
  end

  def build_message_v0(
        header,
        static_account_keys,
        blockhash,
        compiled_instructions,
        address_table_lookups
      ) do
    %{
      header: header,
      static_account_keys: static_account_keys,
      blockhash: blockhash,
      compiled_instructions: compiled_instructions,
      address_table_lookups: address_table_lookups
    }
  end

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
      lookup_keys =
        Enum.flat_map(lookups, fn l ->
          Enum.map(l.writable_indexes ++ l.readonly_indexes, fn _ -> nil end)
        end)

      # For now, we don't have the actual lookup table keys, so we only use static keys
      # In a real implementation, you would fetch the lookup table accounts and insert their keys here
      full_accounts = account_keys ++ lookup_keys
      _indices = Enum.into(Enum.with_index(full_accounts, &{&2, &1}), %{})

      # Resolve instructions
      instructions =
        Enum.map(raw_instructions, fn {program_idx, account_indices, data} ->
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
      {<<>>, 0} ->
        {[], <<>>}

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
      CompactArray.to_iolist(encode_instructions(ixs))
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
  Returns {transaction, extras} or :error
  """
  def parse_with_lookup(encoded, rpc_url) do
    case encoded do
      <<0x80, rest::binary>> ->
        with {signatures, message, _} <- CompactArray.decode_and_split(rest, 64),
             <<header::binary-size(3), contents::binary>> <- message,
             {account_keys, contents, _key_count} <- CompactArray.decode_and_split(contents, 32),
             <<blockhash::binary-size(32), contents::binary>> <- contents,
             {lookups, contents} <- parse_address_table_lookups(contents),
             {:ok, raw_instructions} <- extract_instructions(contents) do
          # Fetch and parse lookup table keys from the network
          lookup_keys =
            Enum.flat_map(lookups, fn lookup ->
              keys = fetch_lookup_table_keys(lookup.account_key, rpc_url)
              Enum.map(lookup.writable_indexes ++ lookup.readonly_indexes, &Enum.at(keys, &1))
            end)

          full_accounts = account_keys ++ lookup_keys
          # Resolve instructions
          instructions =
            Enum.map(raw_instructions, fn {program_idx, account_indices, data} ->
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

      _ ->
        parse(encoded)
    end
  end

  def fetch_lookup_table_keys(table_pubkey, rpc_url) do
    req = Solana.RPC.Request.get_account_info(table_pubkey, encoding: "base64")

    case rpc_client().send(rpc_url, req) do
      {:ok, %{body: %{"result" => %{"value" => %{"data" => [b64, "base64"]}}}}} ->
        data = Base.decode64!(b64)
        parse_lookup_table_account_data(data)

      _ ->
        []
    end
  end

  def parse_lookup_table_account_data(data) do
    # TODO: we need to parse the meta eventually
    <<_meta::binary-size(56), rest::binary>> = data

    for <<key::binary-size(32) <- rest>>, do: key
  end

  defp rpc_client do
    Application.get_env(:solana, :rpc_client, Solana.RPC)
  end

  defp decode58!(s) do
    case B58.decode58(s) do
      {:ok, decoded} -> decoded
      _ -> raise ArgumentError, "invalid base58 string"
    end
  end
end
