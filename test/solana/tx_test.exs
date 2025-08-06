defmodule Solana.TransactionTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Solana, only: [pubkey!: 1]

  import Mox

  setup :verify_on_exit!

  alias Solana.{Transaction, Instruction, Account}
  alias Solana.AddressTableHelper

  describe "to_binary/1" do
    test "fails if there's no blockhash" do
      payer = Solana.keypair()
      program = Solana.keypair() |> pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [
          %Account{signer?: true, writable?: true, key: pubkey!(payer)}
        ]
      }

      tx = %Transaction{payer: pubkey!(payer), instructions: [ix], signers: [payer]}
      assert Transaction.to_binary(tx) == {:error, :no_blockhash}
    end

    test "fails if there's no payer" do
      blockhash = Solana.keypair() |> pubkey!()
      program = Solana.keypair() |> pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [
          %Account{key: blockhash}
        ]
      }

      tx = %Transaction{instructions: [ix], blockhash: blockhash}
      assert Transaction.to_binary(tx) == {:error, :no_payer}
    end

    test "fails if there's no instructions" do
      payer = Solana.keypair()
      blockhash = Solana.keypair() |> pubkey!()
      tx = %Transaction{payer: pubkey!(payer), blockhash: blockhash}
      assert Transaction.to_binary(tx) == {:error, :no_instructions}
    end

    test "fails if an instruction doesn't have a program" do
      blockhash = Solana.keypair() |> pubkey!()
      payer = Solana.keypair()

      ix = %Instruction{
        accounts: [
          %Account{key: pubkey!(payer), writable?: true, signer?: true}
        ]
      }

      tx = %Transaction{
        payer: pubkey!(payer),
        instructions: [ix],
        blockhash: blockhash,
        signers: [payer]
      }

      assert capture_log(fn -> Transaction.to_binary(tx) end) =~ "index 0"
    end

    test "fails if a signer is missing or if there's unnecessary signers" do
      blockhash = Solana.keypair() |> pubkey!()
      program = Solana.keypair() |> pubkey!()
      payer = Solana.keypair()
      signer = Solana.keypair()

      ix = %Instruction{
        program: program,
        accounts: [
          %Account{key: pubkey!(payer), writable?: true, signer?: true}
        ]
      }

      tx = %Transaction{payer: pubkey!(payer), instructions: [ix], blockhash: blockhash}
      assert Transaction.to_binary(tx) == {:error, :mismatched_signers}

      assert Transaction.to_binary(%{tx | signers: [payer, signer]}) ==
               {:error, :mismatched_signers}
    end

    test "places accounts in order (payer first)" do
      payer = Solana.keypair()
      signer = Solana.keypair()
      read_only = Solana.keypair()
      program = Solana.keypair() |> pubkey!()
      blockhash = Solana.keypair() |> pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [
          %Account{signer?: true, key: pubkey!(read_only)},
          %Account{signer?: true, writable?: true, key: pubkey!(signer)},
          %Account{signer?: true, writable?: true, key: pubkey!(payer)}
        ]
      }

      tx = %Transaction{
        payer: pubkey!(payer),
        instructions: [ix],
        blockhash: blockhash,
        signers: [payer, signer, read_only]
      }

      {:ok, tx_bin} = Transaction.to_binary(tx)
      {_, extras} = Transaction.parse(tx_bin)

      assert [pubkey!(payer), pubkey!(signer), pubkey!(read_only)] ==
               extras
               |> Keyword.get(:accounts)
               |> Enum.map(& &1.key)
               |> Enum.take(3)
    end

    test "payer is writable and a signer" do
      payer = Solana.keypair()
      read_only = Solana.keypair()
      program = Solana.keypair() |> pubkey!()
      blockhash = Solana.keypair() |> pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [%Account{key: pubkey!(payer)}, %Account{key: pubkey!(read_only)}]
      }

      tx = %Transaction{
        payer: pubkey!(payer),
        instructions: [ix],
        blockhash: blockhash,
        signers: [payer]
      }

      {:ok, tx_bin} = Transaction.to_binary(tx)
      {_, extras} = Transaction.parse(tx_bin)

      [actual_payer | _] = Keyword.get(extras, :accounts)

      assert actual_payer.key == pubkey!(payer)
      assert actual_payer.writable?
      assert actual_payer.signer?
    end

    test "sets up the header correctly" do
      payer = Solana.keypair()
      writable = Solana.keypair()
      signer = Solana.keypair()
      read_only = Solana.keypair()
      program = Solana.keypair() |> pubkey!()
      blockhash = Solana.keypair() |> pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [
          %Account{key: pubkey!(read_only)},
          %Account{writable?: true, key: pubkey!(writable)},
          %Account{signer?: true, key: pubkey!(signer)},
          %Account{signer?: true, writable?: true, key: pubkey!(payer)}
        ]
      }

      tx = %Transaction{
        payer: pubkey!(payer),
        instructions: [ix],
        blockhash: blockhash,
        signers: [payer, signer]
      }

      {:ok, tx_bin} = Transaction.to_binary(tx)
      {_, extras} = Transaction.parse(tx_bin)

      # 2 signers, one read-only signer, 2 read-only non-signers (read_only and
      # program)
      assert Keyword.get(extras, :header) == <<2, 1, 2>>
    end

    test "dedups signatures and accounts" do
      from = Solana.keypair()
      to = Solana.keypair()
      program = Solana.keypair() |> pubkey!()
      blockhash = Solana.keypair() |> pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [
          %Account{key: pubkey!(to)},
          %Account{signer?: true, writable?: true, key: pubkey!(from)}
        ]
      }

      tx = %Transaction{
        payer: pubkey!(from),
        instructions: [ix, ix],
        blockhash: blockhash,
        signers: [from]
      }

      {:ok, tx_bin} = Transaction.to_binary(tx)
      {_, extras} = Transaction.parse(tx_bin)

      assert [_] = Keyword.get(extras, :signatures)
      assert length(Keyword.get(extras, :accounts)) == 3
    end

    test "to_binary/1 encodes address table lookups for versioned tx" do
      payer = Solana.keypair()
      blockhash = Solana.keypair() |> Solana.pubkey!()
      program = Solana.keypair() |> Solana.pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [%Account{key: Solana.pubkey!(payer), writable?: true, signer?: true}]
      }

      lookup_table_pubkey = :crypto.strong_rand_bytes(32)
      lookup_key = :crypto.strong_rand_bytes(32)

      tx = %Transaction{
        payer: Solana.pubkey!(payer),
        instructions: [ix],
        blockhash: blockhash,
        signers: [payer],
        version: 1,
        address_table_lookups: [
          %Transaction.AddressTableLookup{
            account_key: lookup_table_pubkey,
            writable_indexes: [],
            readonly_indexes: [0]
          }
        ]
      }

      assert {:ok, bin} = Transaction.to_binary(tx)
      assert is_binary(bin)
      assert :binary.first(bin) == 0x80
      # The address table lookup key sequence should be present in the binary
      assert :binary.match(bin, lookup_key)
      # The lookup count byte (1) should be present before the key
      assert :binary.match(bin, <<1>> <> lookup_key)
    end

    test "encodes provided transaction and checks size is less than 1232 bytes" do
      instruction_data = Jason.decode!(File.read!("test/support/instructions.json"))

      lookup_table_accounts =
        Jason.decode!(File.read!("test/support/address_lookup_table_accounts.json"))
        |> Enum.map(fn lookup ->
          %{
            key: lookup["key"],
            state: %{addresses: lookup["state"]["addresses"]}
          }
        end)

      # Extract swap instruction details
      swap_ix = instruction_data["swapInstruction"]
      program = Solana.pubkey(swap_ix["programId"]) |> elem(1)

      # Map accounts for the instruction
      accounts =
        Enum.map(swap_ix["accounts"], fn account ->
          %{
            key: account["pubkey"],
            writable?: account["isWritable"]
          }
        end)

      # Create the instruction
      ix = %Solana.Instruction{
        data: Base.decode64!(swap_ix["data"]),
        program: program,
        accounts:
          Enum.map(accounts, fn %{key: k, writable?: w} ->
            {:ok, key} = Solana.pubkey(k)
            %Solana.Account{key: key, writable?: w, signer?: false}
          end)
      }

      blockhash = instruction_data["blockhashWithMetadata"]["blockhash"] |> :binary.list_to_bin()
      payer = Solana.pubkey!("11111111111111111111111111111112")

       compiled_keys = Transaction.compile_keys([ix], payer)
       {address_table_lookups, account_keys_from_lookups, updated_compiled_keys} = Transaction.process_address_lookup_tables(lookup_table_accounts, compiled_keys)
       {header, static_account_keys} = Transaction.get_message_components(updated_compiled_keys)
       message_account_keys = Transaction.build_message_account_keys(static_account_keys, account_keys_from_lookups)
       compiled_instructions = Transaction.compile_instructions_v0([ix], message_account_keys)
      message = Transaction.build_message_v0(header, static_account_keys, blockhash, compiled_instructions, address_table_lookups)
      encoded_message = Transaction.encode_message(message)

      assert Base.encode16(encoded_message, case: :lower) == reference_bin()

      tx = %Solana.Transaction{
        payer: payer,
        blockhash: blockhash,
        instructions: [ix],
        signers: [{:crypto.strong_rand_bytes(64), payer}],
        version: 1,
        address_table_lookups: lookup_table_accounts
      }

      {:ok, bin} = Solana.Transaction.to_binary(tx)
      dbg(bin, limit: :infinity)
      dbg(byte_size(bin))
      assert byte_size(bin) < 1232
    end

    test "v0 transaction builds address_table_lookups automatically and encodes < 1232 bytes" do
      lookup_table_addresses = [
        "9AKCoNoAGYLW71TwTHY9e7KrZUWWL3c7VtHKb66NT3EV",
        "DHX2A6WncCGUaPVMsZefarm8aPJNXvG2VSB621MkuwYF"
      ]

      lookup_table_accounts = [
        %{
          address: "9AKCoNoAGYLW71TwTHY9e7KrZUWWL3c7VtHKb66NT3EV",
          addresses: [
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "BQ72nSv9f3PRyRKCBnHLVrerrv37CYTHm5h3s9VSGQDV",
            "BcPXor1Jb2XaHcyuQdnTN4ZVSKq5hq5JS892jBc4d8jd"
          ]
        },
        %{
          address: "DHX2A6WncCGUaPVMsZefarm8aPJNXvG2VSB621MkuwYF",
          addresses: [
            "DLXpJDG8fLZ554x8LVP3uSoNQQgdo3JtkiVSQ21YdjEJ",
            "7u7cD7NxcZEuzRCBaYo8uVpotRdqZwez47vvuwzCov43"
          ]
        }
      ]

      # Example accounts (some from lookup tables, some static)
      accounts = [
        %{key: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", writable?: false},
        %{key: "BQ72nSv9f3PRyRKCBnHLVrerrv37CYTHm5h3s9VSGQDV", writable?: false},
        %{key: "BcPXor1Jb2XaHcyuQdnTN4ZVSKq5hq5JS892jBc4d8jd", writable?: true},
        %{key: "DLXpJDG8fLZ554x8LVP3uSoNQQgdo3JtkiVSQ21YdjEJ", writable?: true},
        %{key: "7u7cD7NxcZEuzRCBaYo8uVpotRdqZwez47vvuwzCov43", writable?: true},
        # static
        %{key: "Sysvar1nstructions1111111111111111111111111", writable?: false}
      ]

      # Use the helper to build address_table_lookups
      address_table_lookups =
        Solana.AddressTableHelper.build_address_table_lookups(accounts, lookup_table_accounts)

      # Build a v0 transaction
      {:ok, payer} = Solana.pubkey("BcPXor1Jb2XaHcyuQdnTN4ZVSKq5hq5JS892jBc4d8jd")

      blockhash =
        <<229, 201, 98, 32, 6, 39, 168, 197, 110, 211, 36, 122, 192, 138, 190, 221, 117, 247, 157,
          221, 236, 99, 232, 98, 192, 55, 64, 27, 113, 40, 75, 130>>

      {:ok, program} = Solana.pubkey("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4")

      ix = %Solana.Instruction{
        data:
          <<193, 32, 155, 51, 65, 214, 156, 129, 5, 2, 0, 0, 0, 61, 1, 100, 0, 1, 26, 100, 1, 2,
            64, 75, 76, 0, 0, 0, 0, 0, 226, 94, 215, 1, 0, 0, 0, 0, 50, 0, 0>>,
        program: program,
        accounts:
          Enum.map(accounts, fn %{key: k, writable?: w} ->
            {:ok, key} = Solana.pubkey(k)
            %Solana.Account{key: key, writable?: w, signer?: false}
          end)
      }

      tx = %Solana.Transaction{
        payer: payer,
        blockhash: blockhash,
        instructions: [ix],
        signers: [{:crypto.strong_rand_bytes(64), payer}],
        version: 1,
        address_table_lookups: address_table_lookups
      }

      {:ok, bin} = Solana.Transaction.to_binary(tx)
      assert byte_size(bin) < 1232
    end
  end

  describe "parse/1" do
    test "cannot parse an empty string" do
      assert :error = Transaction.parse("")
    end

    test "cannot parse an improperly encoded transaction" do
      payer = Solana.keypair()
      signer = Solana.keypair()
      read_only = Solana.keypair()
      program = Solana.keypair() |> pubkey!()
      blockhash = Solana.keypair() |> pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [
          %Account{signer?: true, key: pubkey!(read_only)},
          %Account{signer?: true, writable?: true, key: pubkey!(signer)},
          %Account{signer?: true, writable?: true, key: pubkey!(payer)}
        ]
      }

      tx = %Transaction{
        payer: pubkey!(payer),
        instructions: [ix],
        blockhash: blockhash,
        signers: [payer, signer, read_only]
      }

      {:ok, <<_::8, clipped_tx::binary>>} = Transaction.to_binary(tx)
      assert :error = Transaction.parse(clipped_tx)
    end

    test "can parse a properly encoded tranaction" do
      from = Solana.keypair()
      to = Solana.keypair()
      program = Solana.keypair() |> pubkey!()
      blockhash = Solana.keypair() |> pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [
          %Account{key: pubkey!(to)},
          %Account{signer?: true, writable?: true, key: pubkey!(from)}
        ],
        data: <<1, 2, 3>>
      }

      tx = %Transaction{
        payer: pubkey!(from),
        instructions: [ix, ix],
        blockhash: blockhash,
        signers: [from]
      }

      {:ok, tx_bin} = Transaction.to_binary(tx)
      {actual, extras} = Transaction.parse(tx_bin)

      assert [_signature] = Keyword.get(extras, :signatures)

      assert actual.payer == pubkey!(from)
      assert actual.instructions == [ix, ix]
      assert actual.blockhash == blockhash
    end
  end

  describe "decode/1" do
    test "fails for signatures which are too short" do
      encoded = B58.encode58(Enum.into(1..63, <<>>, &<<&1::8>>))
      assert {:error, _} = Transaction.decode(encoded)
      assert {:error, _} = Transaction.decode("12345")
    end

    test "fails for signatures which are too long" do
      encoded = B58.encode58(<<3, 0::64*8>>)
      assert {:error, _} = Transaction.decode(encoded)
    end

    test "fails for signatures which aren't base58-encoded" do
      assert {:error, _} =
               Transaction.decode(
                 "0x300000000000000000000000000000000000000000000000000000000000000000000"
               )

      assert {:error, _} =
               Transaction.decode(
                 "0x300000000000000000000000000000000000000000000000000000000000000"
               )

      assert {:error, _} =
               Transaction.decode(
                 "135693854574979916511997248057056142015550763280047535983739356259273198796800000"
               )
    end

    test "works for regular signatures" do
      assert {:ok, <<3, 0::63*8>>} =
               Transaction.decode(
                 "4Umk1E47BhUNBHJQGJto6i5xpATqVs8UxW11QjpoVnBmiv7aZJyG78yVYj99SrozRa9x7av8p3GJmBuzvhpUHDZ"
               )
    end
  end

  describe "decode!/1" do
    test "throws for signatures which aren't base58-encoded" do
      assert_raise ArgumentError, fn ->
        Transaction.decode!(
          "0x300000000000000000000000000000000000000000000000000000000000000000000"
        )
      end

      assert_raise ArgumentError, fn ->
        Transaction.decode!("0x300000000000000000000000000000000000000000000000000000000000000")
      end

      assert_raise ArgumentError, fn ->
        Transaction.decode!(
          "135693854574979916511997248057056142015550763280047535983739356259273198796800000"
        )
      end
    end

    test "works for regular signatures" do
      assert <<3, 0::63*8>> ==
               Transaction.decode!(
                 "4Umk1E47BhUNBHJQGJto6i5xpATqVs8UxW11QjpoVnBmiv7aZJyG78yVYj99SrozRa9x7av8p3GJmBuzvhpUHDZ"
               )
    end
  end

  describe "versioned transaction stubs" do
    test "to_binary/1 returns {:ok, binary} for versioned tx with no address table lookups" do
      payer = Solana.keypair()
      blockhash = Solana.keypair() |> Solana.pubkey!()
      program = Solana.keypair() |> Solana.pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [%Account{key: Solana.pubkey!(payer), writable?: true, signer?: true}]
      }

      tx = %Transaction{
        payer: Solana.pubkey!(payer),
        instructions: [ix],
        blockhash: blockhash,
        signers: [payer],
        version: 1
      }

      assert {:ok, bin} = Transaction.to_binary(tx)
      assert is_binary(bin)
      assert :binary.first(bin) == 0x80
    end

    test "parse/1 returns :error for versioned tx binary stub" do
      # 0x80 is the version prefix for v0 versioned transactions
      versioned_bin =
        <<0x80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
          23, 24, 25, 26, 27, 28, 29, 30, 31>>

      assert Transaction.parse(versioned_bin) == :error
    end

    test "round-trip encode/parse for versioned tx without address table lookups" do
      payer = Solana.keypair()
      blockhash = Solana.keypair() |> Solana.pubkey!()
      program = Solana.keypair() |> Solana.pubkey!()

      ix = %Instruction{
        program: program,
        accounts: [%Account{key: Solana.pubkey!(payer), writable?: true, signer?: true}]
      }

      tx = %Transaction{
        payer: Solana.pubkey!(payer),
        instructions: [ix],
        blockhash: blockhash,
        signers: [payer],
        version: 1
      }

      assert {:ok, bin} = Transaction.to_binary(tx)
      assert {parsed, extras} = Transaction.parse(bin)
      assert parsed.version == 1
      assert parsed.blockhash == blockhash
      assert parsed.address_table_lookups == []
      assert Keyword.has_key?(extras, :accounts)
      assert Keyword.has_key?(extras, :signatures)
    end

    test "round-trip encode/parse for versioned tx with address table lookups" do
      _payer = Solana.keypair()
      blockhash = Solana.keypair() |> Solana.pubkey!()
      _program = Solana.keypair() |> Solana.pubkey!()
      payer_key = :crypto.strong_rand_bytes(32)
      program_key = :crypto.strong_rand_bytes(32)
      lookup_table_pubkey = :crypto.strong_rand_bytes(32)
      lookup_key = :crypto.strong_rand_bytes(32)

      ix = %Instruction{
        program: program_key,
        accounts: [
          %Account{key: payer_key, writable?: true, signer?: true},
          %Account{key: lookup_key, writable?: false, signer?: false}
        ]
      }

      lookup = %Transaction.AddressTableLookup{
        account_key: lookup_table_pubkey,
        writable_indexes: [],
        readonly_indexes: [0]
      }

      tx = %Transaction{
        payer: payer_key,
        instructions: [ix],
        blockhash: blockhash,
        signers: [{:crypto.strong_rand_bytes(64), payer_key}],
        version: 1,
        address_table_lookups: [lookup]
      }

      assert {:ok, bin} = Transaction.to_binary(tx)
      assert {parsed, extras} = Transaction.parse(bin)
      assert parsed.version == 1
      assert parsed.blockhash == blockhash
      assert length(parsed.address_table_lookups) == 1
    end

    test "parse_with_lookup/3 resolves lookup table keys for versioned tx (with Mox expect)" do
      lookup_key = :crypto.strong_rand_bytes(32)
      lookup_table_pubkey = :crypto.strong_rand_bytes(32)
      # Set up Mox for Rpc
      Solana.RPC.Mock
      |> Mox.expect(:send, fn _rpc_url, req ->
        assert {"getAccountInfo", [_, %{"encoding" => "base64"}]} = req

        data =
          :crypto.strong_rand_bytes(32) <>
            :crypto.strong_rand_bytes(8) <> <<1::little-32>> <> lookup_key

        b64 = Base.encode64(data)
        {:ok, %{body: [%{"result" => %{"value" => %{"data" => [b64, "base64"]}}}]}}
      end)

      _payer = Solana.keypair()
      blockhash = Solana.keypair() |> Solana.pubkey!()
      _program = Solana.keypair() |> Solana.pubkey!()
      payer_key = :crypto.strong_rand_bytes(32)
      program_key = :crypto.strong_rand_bytes(32)

      ix = %Instruction{
        program: program_key,
        accounts: [
          %Account{key: payer_key, writable?: true, signer?: true},
          %Account{key: lookup_key, writable?: false, signer?: false}
        ]
      }

      lookup = %Transaction.AddressTableLookup{
        account_key: lookup_table_pubkey,
        writable_indexes: [],
        readonly_indexes: [0]
      }

      tx = %Transaction{
        payer: payer_key,
        instructions: [ix],
        blockhash: blockhash,
        signers: [{:crypto.strong_rand_bytes(64), payer_key}],
        version: 1,
        address_table_lookups: [lookup]
      }

      # Encode the transaction
      {:ok, bin} = Transaction.to_binary(tx)
      # Use parse_with_lookup, which should trigger the Mox expect
      {parsed, extras} = Transaction.parse_with_lookup(bin, "mock-url")
      # The full account list should include the static and lookup key
      assert Enum.any?(Keyword.get(extras, :accounts), &(&1 == lookup_key))
      # The instruction should reference the lookup key
      assert Enum.any?(List.first(parsed.instructions).accounts, &(&1.key == lookup_key))
      assert parsed.version == 1
      assert parsed.blockhash == blockhash
      assert length(parsed.address_table_lookups) == 1
    end

    test "round-trip encode/parse for versioned tx with address table lookups (compression checks)" do
      payer_key = :crypto.strong_rand_bytes(32)
      program_key = :crypto.strong_rand_bytes(32)
      lookup_table_pubkey = :crypto.strong_rand_bytes(32)
      lookup_key1 = :crypto.strong_rand_bytes(32)
      lookup_key2 = :crypto.strong_rand_bytes(32)
      blockhash = Solana.keypair() |> Solana.pubkey!()
      # Instruction uses payer (static) and two ALT keys
      ix = %Instruction{
        program: program_key,
        accounts: [
          %Account{key: payer_key, writable?: true, signer?: true},
          %Account{key: lookup_key1, writable?: false, signer?: false},
          %Account{key: lookup_key2, writable?: true, signer?: false}
        ]
      }

      lookup = %Transaction.AddressTableLookup{
        account_key: lookup_table_pubkey,
        # lookup_key2
        writable_indexes: [1],
        # lookup_key1
        readonly_indexes: [0]
      }

      tx = %Transaction{
        payer: payer_key,
        instructions: [ix],
        blockhash: blockhash,
        signers: [{:crypto.strong_rand_bytes(64), payer_key}],
        version: 1,
        address_table_lookups: [lookup]
      }

      assert {:ok, bin} = Transaction.to_binary(tx)
      assert {parsed, extras} = Transaction.parse(bin)
      # Compression checks
      accounts = Keyword.get(extras, :accounts)
      # payer, program, (maybe more if not in ALT)
      static_accounts = Enum.take(accounts, 3)
      alt_accounts = Enum.drop(accounts, 3)
      # Static accounts should include payer and program, not ALT keys
      assert Enum.any?(static_accounts, &(&1 == payer_key))
      assert Enum.any?(static_accounts, &(&1 == program_key))
      refute Enum.any?(static_accounts, &(&1 == lookup_key1))
      refute Enum.any?(static_accounts, &(&1 == lookup_key2))
      # ALT accounts should include lookup1 and lookup_key2
      assert Enum.any?(alt_accounts, &(&1 == lookup_key1))
      assert Enum.any?(alt_accounts, &(&1 == lookup_key2))
      # Address table lookups should have correct indices
      [lookup_struct] = parsed.address_table_lookups
      assert lookup_struct.account_key == lookup_table_pubkey
      assert lookup_struct.readonly_indexes == [0]
      assert lookup_struct.writable_indexes == [1]
      # Instruction account indices: static first, then ALT
      ix_parsed = List.first(parsed.instructions)
      # Should reference payer (static), lookup_key1 (ALT), lookup_key2 (ALT)
      assert Enum.map(ix_parsed.accounts, & &1.key) == [payer_key, lookup_key1, lookup_key2]
    end

    test "v0 transaction with multiple ALTs and overlapping accounts (compression edge cases)" do
      payer_key = :crypto.strong_rand_bytes(32)
      program_key = :crypto.strong_rand_bytes(32)
      alt1_pubkey = :crypto.strong_rand_bytes(32)
      alt2_pubkey = :crypto.strong_rand_bytes(32)
      shared_key = :crypto.strong_rand_bytes(32)
      alt1_key = :crypto.strong_rand_bytes(32)
      alt2_key = :crypto.strong_rand_bytes(32)
      blockhash = Solana.keypair() |> Solana.pubkey!()
      # shared_key is in both ALTs, but should only be referenced from the first
      ix = %Instruction{
        program: program_key,
        accounts: [
          %Account{key: payer_key, writable?: true, signer?: true},
          %Account{key: shared_key, writable?: false, signer?: false},
          %Account{key: alt1_key, writable?: false, signer?: false},
          %Account{key: alt2_key, writable?: false, signer?: false}
        ]
      }

      lookup1 = %Transaction.AddressTableLookup{
        account_key: alt1_pubkey,
        writable_indexes: [],
        # shared_key, alt1_key
        readonly_indexes: [0, 1]
      }

      lookup2 = %Transaction.AddressTableLookup{
        account_key: alt2_pubkey,
        writable_indexes: [],
        # shared_key, alt2_key
        readonly_indexes: [0, 1]
      }

      tx = %Transaction{
        payer: payer_key,
        instructions: [ix],
        blockhash: blockhash,
        signers: [{:crypto.strong_rand_bytes(64), payer_key}],
        version: 1,
        address_table_lookups: [lookup1, lookup2]
      }

      assert {:ok, bin} = Transaction.to_binary(tx)
      assert {parsed, extras} = Transaction.parse(bin)
      accounts = Keyword.get(extras, :accounts)
      static_accounts = Enum.take(accounts, 3)
      alt_accounts = Enum.drop(accounts, 3)
      # shared_key should only appear once in the ALT accounts (first ALT)
      assert Enum.count(Enum.filter(alt_accounts, &(&1.key == shared_key))) == 1
      # All ALT keys should be present
      assert Enum.any?(alt_accounts, &(&1.key == alt1_key))
      assert Enum.any?(alt_accounts, &(&1.key == alt2_key))
      # Static accounts should not include ALT keys
      refute Enum.any?(static_accounts, &(&1.key == shared_key))
      refute Enum.any?(static_accounts, &(&1.key == alt1_key))
      refute Enum.any?(static_accounts, &(&1.key == alt2_key))
      # Address table lookups should be correct
      [lookup1_parsed, lookup2_parsed] = parsed.address_table_lookups
      assert lookup1_parsed.account_key == alt1_pubkey
      assert lookup2_parsed.account_key == alt2_pubkey
      # Instruction account indices: static first, then ALT (shared_key from first ALT)
      ix_parsed = List.first(parsed.instructions)
      assert Enum.map(ix_parsed.accounts, & &1.key) == [payer_key, shared_key, alt1_key, alt2_key]
    end
  end

  defp reference_bin do
    Base.encode16(<<128, 1, 0, 5, 12, 126, 197, 119, 48, 59, 129, 9, 85, 192, 221, 241, 170, 158, 140, 12, 244,
      158, 232, 48, 221, 117, 175, 130, 101, 176, 65, 247, 174, 54, 121, 56, 245, 219, 237, 142,
      191, 91, 190, 152, 61, 82, 26, 140, 5, 78, 105, 139, 150, 172, 22, 210, 1, 184, 114, 24, 84,
      240, 112, 218, 191, 67, 134, 2, 167, 88, 239, 103, 127, 181, 99, 94, 100, 115, 114, 75, 112,
      225, 107, 100, 5, 84, 3, 78, 164, 122, 28, 123, 63, 205, 136, 133, 60, 65, 93, 50, 84, 231,
      227, 72, 142, 86, 218, 198, 109, 211, 196, 228, 6, 133, 61, 42, 122, 144, 97, 208, 154, 127,
      168, 243, 247, 226, 146, 191, 178, 73, 149, 131, 21, 217, 175, 13, 57, 224, 125, 63, 12,
      176, 13, 21, 41, 121, 7, 185, 119, 246, 155, 132, 158, 237, 37, 43, 200, 226, 101, 246, 31,
      65, 203, 47, 166, 11, 72, 7, 79, 117, 184, 234, 48, 105, 201, 237, 63, 6, 188, 50, 25, 120,
      42, 228, 205, 142, 92, 157, 55, 73, 130, 86, 177, 152, 75, 157, 80, 3, 175, 245, 229, 169,
      43, 125, 251, 114, 27, 231, 43, 212, 81, 245, 66, 23, 164, 216, 134, 200, 24, 200, 143, 243,
      24, 145, 123, 254, 181, 18, 254, 4, 121, 213, 91, 242, 49, 192, 110, 238, 116, 197, 110,
      206, 104, 21, 7, 253, 177, 178, 222, 163, 244, 142, 81, 2, 177, 205, 162, 86, 188, 19, 143,
      58, 184, 144, 63, 183, 53, 202, 177, 198, 124, 89, 175, 72, 87, 237, 246, 27, 10, 248, 50,
      165, 10, 124, 89, 227, 33, 145, 158, 14, 200, 169, 188, 180, 63, 250, 39, 245, 215, 246, 74,
      116, 192, 155, 31, 41, 88, 121, 222, 75, 9, 171, 54, 223, 201, 221, 81, 75, 50, 26, 167,
      179, 140, 229, 232, 231, 74, 217, 108, 227, 101, 159, 211, 19, 81, 0, 40, 75, 247, 120, 4,
      91, 133, 16, 168, 243, 78, 73, 140, 146, 46, 238, 111, 195, 5, 248, 105, 82, 97, 209, 74,
      172, 197, 188, 14, 236, 99, 93, 168, 112, 90, 31, 112, 163, 158, 227, 90, 154, 207, 11, 248,
      242, 44, 198, 206, 73, 1, 157, 122, 65, 159, 89, 55, 201, 69, 203, 4, 134, 223, 42, 119, 66,
      241, 54, 89, 107, 63, 236, 120, 144, 98, 51, 42, 62, 104, 117, 123, 108, 234, 146, 121, 1,
      7, 65, 27, 8, 0, 1, 2, 3, 4, 28, 32, 7, 7, 9, 7, 47, 23, 10, 11, 24, 25, 2, 5, 26, 48, 49,
      8, 27, 29, 27, 8, 12, 5, 13, 6, 14, 15, 16, 17, 30, 33, 8, 31, 32, 6, 3, 18, 27, 27, 19, 20,
      21, 22, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 7, 56, 193, 32, 155, 51, 65,
      214, 156, 129, 4, 3, 0, 0, 0, 58, 1, 100, 0, 1, 17, 1, 100, 1, 2, 43, 5, 5, 12, 0, 0, 0, 21,
      0, 0, 0, 100, 2, 3, 232, 3, 0, 0, 0, 0, 0, 0, 126, 3, 0, 0, 0, 0, 0, 0, 50, 0, 0, 3, 148,
      187, 197, 83, 10, 200, 93, 65, 98, 63, 228, 114, 107, 167, 57, 236, 61, 208, 255, 46, 172,
      134, 73, 247, 1, 127, 41, 22, 180, 225, 190, 168, 6, 238, 235, 233, 242, 237, 241, 5, 10, 0,
      9, 236, 70, 182, 110, 133, 91, 242, 147, 203, 71, 129, 251, 209, 206, 35, 119, 82, 233, 192,
      19, 33, 111, 188, 104, 229, 31, 69, 225, 9, 110, 182, 129, 177, 254, 5, 193, 24, 7, 47, 61,
      15, 2, 213, 198, 117, 5, 113, 14, 201, 124, 101, 104, 106, 67, 1, 135, 243, 115, 121, 214,
      132, 181, 161, 116, 229, 153, 34, 225, 57, 106, 151, 46, 52, 23, 15, 209, 14, 0, 75, 243,
      145, 168, 29, 103, 61, 186, 51, 240, 4, 12, 18, 13, 11, 3, 15, 14, 16>>, case: :lower)
  end
end
