defmodule Solana.TransactionTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Solana, only: [pubkey!: 1]

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
      versioned_bin = <<0x80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31>>
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
      assert Enum.at(parsed.address_table_lookups, 0).account_key == lookup_table_pubkey
      assert Enum.at(parsed.address_table_lookups, 0).writable_indexes == []
      assert Enum.at(parsed.address_table_lookups, 0).readonly_indexes == [0]
      assert Keyword.has_key?(extras, :accounts)
      assert Keyword.has_key?(extras, :signatures)
      assert Keyword.has_key?(extras, :address_table_lookups)
    end

    test "parse_with_lookup/3 resolves lookup table keys for versioned tx" do
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
      # Encode the transaction
      {:ok, bin} = Transaction.to_binary(tx)
      # Mock fetch function returns [lookup_key] for the lookup table
      fetch_fun = fn _rpc_url, _req ->
        # Simulate get_account_info returning a single key in the table
        data = :crypto.strong_rand_bytes(32) <> :crypto.strong_rand_bytes(8) <> <<1::little-32>> <> lookup_key
        b64 = Base.encode64(data)
        {:ok, %{body: [%{"result" => %{"value" => %{"data" => [b64, "base64"]}}}]}}
      end
      {parsed, extras} = Transaction.parse_with_lookup(bin, "mock-url", fetch_fun)
      # The full account list should include the static and lookup key
      assert Enum.any?(Keyword.get(extras, :accounts), &(&1 == lookup_key))
      # The instruction should reference the lookup key
      assert Enum.any?(List.first(parsed.instructions).accounts, &(&1.key == lookup_key))
      assert parsed.version == 1
      assert parsed.blockhash == blockhash
      assert length(parsed.address_table_lookups) == 1
    end
  end
end
