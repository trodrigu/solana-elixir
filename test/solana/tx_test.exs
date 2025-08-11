defmodule Solana.TransactionTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Solana, only: [pubkey!: 1]

  import Mox

  setup :verify_on_exit!

  alias Solana.{Transaction, Instruction, Account}

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

      assert byte_size(bin) < 1232
    end

    test "v0 transaction builds address_table_lookups automatically and encodes < 1232 bytes" do
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
      assert {parsed, _extras} = Transaction.parse(bin)
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
    "80010002080000000000000000000000000000000000000000000000000000000000000001477012c01cdc20c7124d94f6f71a0e90d0887396ff16cecea27ddd66b1e814b4b69aaf2b9dac6b8d24f4109cb1664c01d23c68140f04f5c6ee886e7f10fbe573089c77c07798a0346ccad57c9037dc8ec64bae5674d62d04fd3b6cc298a65191795a4529c3bc7c233d982df3cad38df781c9567917dd34f3c08e3426abe8a7727422cc224344c5cc3b5c9ad18fa93b721759d02edd14a0a006a7e4b5629c3f100479d55bf231c06eee74c56ece681507fdb1b2dea3f48e5102b1cda256bc138fb43ffa27f5d7f64a74c09b1f295879de4b09ab36dfc9dd514b321aa7b38ce5e8d9feede0ea1dc6f1f30d3888faa8b50d7779dfa7f8aaf7589fd1569da5c0cbb50106150b000102060c0607060d0b00080109020a0304050e24e517cb977ae3ad2a010000001101640001e803000000000000790300000000000032000001c8e5da50ca5b5aece6139c51d8e7ac1da6a71909d452ff277b664d92738f37a4031f9e220409231524"
  end
end
