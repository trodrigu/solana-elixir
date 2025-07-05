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
      # Exact accounts as provided
      accounts = [
        %Solana.Account{key: <<6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169>>, signer?: false, writable?: false},
        %Solana.Account{key: <<172, 26, 227, 208, 135, 242, 146, 55, 6, 37, 72, 247, 12, 76, 4, 174, 194, 169, 149, 105, 73, 134, 231, 203, 180, 103, 82, 6, 33, 211, 134, 48>>, signer?: false, writable?: false},
        %Solana.Account{key: <<157, 165, 172, 116, 127, 61, 108, 104, 47, 113, 145, 40, 116, 91, 205, 192, 14, 113, 164, 27, 39, 16, 199, 51, 122, 47, 136, 189, 117, 132, 203, 212>>, signer?: true, writable?: false},
        %Solana.Account{key: <<183, 77, 31, 35, 232, 221, 5, 189, 244, 67, 163, 170, 149, 191, 217, 65, 215, 108, 155, 93, 36, 219, 20, 213, 222, 131, 48, 238, 226, 69, 34, 59>>, signer?: false, writable?: true},
        %Solana.Account{key: <<233, 212, 72, 139, 7, 254, 57, 155, 26, 145, 85, 229, 130, 27, 105, 125, 67, 1, 108, 10, 60, 79, 59, 188, 162, 175, 180, 29, 1, 99, 48, 87>>, signer?: false, writable?: true},
        %Solana.Account{key: <<192, 167, 138, 134, 184, 31, 163, 35, 58, 223, 152, 137, 51, 153, 8, 181, 110, 185, 71, 12, 49, 170, 181, 196, 176, 231, 195, 59, 252, 139, 49, 191>>, signer?: false, writable?: true},
        %Solana.Account{key: <<160, 113, 2, 127, 115, 211, 192, 206, 223, 99, 139, 92, 157, 88, 35, 111, 201, 58, 33, 43, 53, 187, 150, 91, 231, 16, 149, 121, 139, 112, 126, 239>>, signer?: false, writable?: true},
        %Solana.Account{key: <<198, 250, 122, 243, 190, 219, 173, 58, 61, 101, 243, 106, 171, 201, 116, 49, 177, 187, 228, 194, 210, 246, 224, 228, 124, 166, 2, 3, 69, 47, 93, 97>>, signer?: false, writable?: false},
        %Solana.Account{key: <<163, 20, 167, 170, 3, 43, 231, 16, 229, 136, 114, 85, 23, 1, 169, 23, 90, 122, 55, 127, 38, 161, 248, 55, 234, 71, 184, 250, 129, 217, 78, 0>>, signer?: false, writable?: false},
        %Solana.Account{key: <<4, 121, 213, 91, 242, 49, 192, 110, 238, 116, 197, 110, 206, 104, 21, 7, 253, 177, 178, 222, 163, 244, 142, 81, 2, 177, 205, 162, 86, 188, 19, 143>>, signer?: false, writable?: false},
        %Solana.Account{key: <<4, 121, 213, 91, 242, 49, 192, 110, 238, 116, 197, 110, 206, 104, 21, 7, 253, 177, 178, 222, 163, 244, 142, 81, 2, 177, 205, 162, 86, 188, 19, 143>>, signer?: false, writable?: false},
        %Solana.Account{key: <<180, 63, 250, 39, 245, 215, 246, 74, 116, 192, 155, 31, 41, 88, 121, 222, 75, 9, 171, 54, 223, 201, 221, 81, 75, 50, 26, 167, 179, 140, 229, 232>>, signer?: false, writable?: false},
        %Solana.Account{key: <<4, 121, 213, 91, 242, 49, 192, 110, 238, 116, 197, 110, 206, 104, 21, 7, 253, 177, 178, 222, 163, 244, 142, 81, 2, 177, 205, 162, 86, 188, 19, 143>>, signer?: false, writable?: false},
        %Solana.Account{key: <<6, 155, 232, 110, 201, 175, 101, 235, 74, 97, 79, 217, 155, 142, 146, 84, 125, 160, 20, 95, 171, 94, 128, 74, 219, 89, 77, 179, 231, 58, 39, 27>>, signer?: false, writable?: false},
        %Solana.Account{key: <<172, 26, 227, 208, 135, 242, 146, 55, 6, 37, 72, 247, 12, 76, 4, 174, 194, 169, 149, 105, 73, 134, 231, 203, 180, 103, 82, 6, 33, 211, 134, 48>>, signer?: false, writable?: false},
        %Solana.Account{key: <<69, 167, 110, 83, 33, 167, 235, 108, 178, 101, 236, 81, 121, 174, 39, 0, 182, 155, 211, 46, 65, 189, 203, 221, 222, 57, 122, 79, 33, 190, 60, 127>>, signer?: false, writable?: true},
        %Solana.Account{key: <<161, 241, 251, 140, 5, 0, 34, 191, 180, 24, 245, 53, 254, 78, 95, 164, 157, 151, 253, 109, 141, 103, 232, 191, 32, 230, 250, 95, 173, 248, 197, 220>>, signer?: false, writable?: true},
        %Solana.Account{key: <<46, 114, 218, 226, 246, 153, 246, 36, 193, 115, 53, 14, 184, 151, 53, 181, 50, 12, 111, 219, 129, 249, 175, 9, 91, 194, 12, 162, 186, 75, 156, 169>>, signer?: false, writable?: true},
        %Solana.Account{key: <<119, 4, 122, 56, 28, 57, 21, 56, 247, 163, 186, 66, 186, 254, 132, 29, 69, 63, 38, 213, 46, 113, 166, 100, 67, 246, 175, 30, 221, 116, 138, 253>>, signer?: false, writable?: true},
        %Solana.Account{key: <<233, 212, 72, 139, 7, 254, 57, 155, 26, 145, 85, 229, 130, 27, 105, 125, 67, 1, 108, 10, 60, 79, 59, 188, 162, 175, 180, 29, 1, 99, 48, 87>>, signer?: false, writable?: true},
        %Solana.Account{key: <<6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169>>, signer?: false, writable?: false},
        %Solana.Account{key: <<6, 167, 213, 23, 24, 123, 209, 102, 53, 218, 212, 4, 85, 253, 194, 192, 193, 36, 198, 143, 33, 86, 117, 165, 219, 186, 203, 95, 8, 0, 0, 0>>, signer?: false, writable?: false},
        %Solana.Account{key: <<165, 213, 202, 158, 4, 207, 93, 181, 144, 183, 20, 186, 47, 227, 44, 177, 89, 19, 63, 193, 193, 146, 183, 34, 87, 253, 7, 211, 156, 176, 64, 30>>, signer?: false, writable?: false},
        %Solana.Account{key: <<172, 26, 227, 208, 135, 242, 146, 55, 6, 37, 72, 247, 12, 76, 4, 174, 194, 169, 149, 105, 73, 134, 231, 203, 180, 103, 82, 6, 33, 211, 134, 48>>, signer?: false, writable?: false},
        %Solana.Account{key: <<129, 110, 102, 99, 12, 59, 183, 36, 220, 89, 228, 159, 108, 196, 48, 110, 96, 58, 106, 172, 202, 6, 250, 62, 52, 226, 180, 10, 213, 151, 157, 141>>, signer?: false, writable?: false},
        %Solana.Account{key: <<207, 203, 8, 151, 194, 123, 207, 219, 94, 70, 212, 157, 3, 63, 89, 219, 154, 139, 82, 135, 188, 30, 27, 240, 126, 237, 19, 165, 131, 125, 225, 43>>, signer?: false, writable?: true},
        %Solana.Account{key: <<119, 4, 122, 56, 28, 57, 21, 56, 247, 163, 186, 66, 186, 254, 132, 29, 69, 63, 38, 213, 46, 113, 166, 100, 67, 246, 175, 30, 221, 116, 138, 253>>, signer?: false, writable?: true},
        %Solana.Account{key: <<192, 167, 138, 134, 184, 31, 163, 35, 58, 223, 152, 137, 51, 153, 8, 181, 110, 185, 71, 12, 49, 170, 181, 196, 176, 231, 195, 59, 252, 139, 49, 191>>, signer?: false, writable?: true},
        %Solana.Account{key: <<116, 245, 164, 170, 0, 132, 225, 50, 247, 14, 91, 158, 64, 0, 213, 6, 56, 133, 176, 216, 85, 64, 74, 224, 192, 2, 74, 88, 79, 122, 189, 144>>, signer?: false, writable?: true},
        %Solana.Account{key: <<183, 232, 49, 52, 52, 169, 139, 185, 211, 63, 99, 233, 10, 231, 34, 72, 3, 208, 152, 39, 205, 97, 164, 35, 236, 33, 202, 0, 46, 18, 174, 20>>, signer?: false, writable?: true},
        %Solana.Account{key: <<201, 70, 214, 133, 104, 36, 159, 20, 101, 195, 17, 22, 18, 3, 88, 111, 153, 96, 40, 39, 46, 48, 53, 70, 224, 172, 121, 205, 214, 219, 147, 36>>, signer?: false, writable?: true},
        %Solana.Account{key: <<6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169>>, signer?: false, writable?: false},
        %Solana.Account{key: <<83, 209, 195, 39, 130, 109, 174, 222, 124, 7, 26, 10, 226, 100, 184, 249, 223, 160, 208, 66, 8, 208, 101, 46, 242, 83, 97, 165, 250, 220, 130, 224>>, signer?: false, writable?: true},
        %Solana.Account{key: <<21, 181, 245, 117, 230, 85, 75, 118, 14, 137, 190, 46, 91, 7, 63, 83, 32, 146, 139, 224, 109, 7, 162, 169, 84, 27, 20, 113, 107, 112, 13, 150>>, signer?: false, writable?: true},
        %Solana.Account{key: <<218, 235, 38, 89, 10, 254, 13, 74, 78, 84, 18, 103, 20, 101, 121, 18, 209, 60, 224, 7, 203, 254, 120, 88, 237, 217, 126, 105, 241, 78, 100, 126>>, signer?: false, writable?: true},
        %Solana.Account{key: <<133, 22, 168, 163, 240, 97, 48, 42, 39, 31, 114, 250, 205, 29, 225, 135, 51, 26, 25, 149, 30, 98, 9, 50, 52, 83, 207, 208, 244, 171, 111, 54>>, signer?: false, writable?: true},
        %Solana.Account{key: <<4, 121, 213, 91, 242, 49, 192, 110, 238, 116, 197, 110, 206, 104, 21, 7, 253, 177, 178, 222, 163, 244, 142, 81, 2, 177, 205, 162, 86, 188, 19, 143>>, signer?: false, writable?: false}
      ]
      # Exact address_table_lookups as provided (empty for this legacy example, but you can fill in if you have the binary structure)
      address_table_lookups = [
        %Solana.Transaction.AddressTableLookup{
          account_key: B58.decode58("9AKCoNoAGYLW71TwTHY9e7KrZUWWL3c7VtHKb66NT3EV"),
          writable_indexes: [],
          readonly_indexes: [0, 1, 2]
        },
        %Solana.Transaction.AddressTableLookup{
          account_key: B58.decode58("DHX2A6WncCGUaPVMsZefarm8aPJNXvG2VSB621MkuwYF"),
          writable_indexes: [0, 1],
          readonly_indexes: []
        }
      ]
      payer = <<157, 165, 172, 116, 127, 61, 108, 104, 47, 113, 145, 40, 116, 91, 205, 192, 14, 113, 164, 27, 39, 16, 199, 51, 122, 47, 136, 189, 117, 132, 203, 212>>
      blockhash = <<110, 91, 81, 227, 215, 46, 41, 83, 233, 178, 37, 54, 65, 184, 214, 192, 168, 226, 161, 43, 163, 168, 92, 122, 33, 199, 208, 19, 127, 4, 117, 13>>
      program = <<4, 121, 213, 91, 242, 49, 192, 110, 238, 116, 197, 110, 206, 104, 21, 7, 253, 177, 178, 222, 163, 244, 142, 81, 2, 177, 205, 162, 86, 188, 19, 143>>
      ix = %Solana.Instruction{
        data: <<193, 32, 155, 51, 65, 214, 156, 129, 5, 2, 0, 0, 0, 61, 1, 100, 0, 1, 26, 100, 1, 2, 64, 75, 76, 0, 0, 0, 0, 0, 226, 94, 215, 1, 0, 0, 0, 0, 50, 0, 0>>,
        program: program,
        accounts: accounts
      }
      tx = %Solana.Transaction{
        payer: payer,
        blockhash: blockhash,
        instructions: [ix],
        signers: [{<<2, 179, 26, 93, 179, 211, 156, 0, 136, 117, 19, 36, 211, 236, 61, 190, 21, 200, 68, 53, 122, 24, 71, 33, 13, 186, 167, 196, 210, 207, 34, 117>>, payer}],
        version: 1,
        address_table_lookups: address_table_lookups
      }
      {:ok, bin} = Solana.Transaction.to_binary(tx)
      assert byte_size(bin) < 1232
    end

    test "v0 transaction builds address_table_lookups automatically and encodes < 1232 bytes" do
      # Example lookup table addresses (base58)
      lookup_table_addresses = [
        "9AKCoNoAGYLW71TwTHY9e7KrZUWWL3c7VtHKb66NT3EV",
        "DHX2A6WncCGUaPVMsZefarm8aPJNXvG2VSB621MkuwYF"
      ]
      # Example lookup table contents (base58 pubkeys)
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
        %{key: "Sysvar1nstructions1111111111111111111111111", writable?: false} # static
      ]
      # Use the helper to build address_table_lookups
      address_table_lookups = Solana.AddressTableHelper.build_address_table_lookups(accounts, lookup_table_accounts)
      # Build a v0 transaction
      payer = B58.decode58("BcPXor1Jb2XaHcyuQdnTN4ZVSKq5hq5JS892jBc4d8jd")
      blockhash = <<229, 201, 98, 32, 6, 39, 168, 197, 110, 211, 36, 122, 192, 138, 190, 221, 117, 247, 157, 221, 236, 99, 232, 98, 192, 55, 64, 27, 113, 40, 75, 130>>
      program = B58.decode58("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4")
      ix = %Solana.Instruction{
        data: <<193, 32, 155, 51, 65, 214, 156, 129, 5, 2, 0, 0, 0, 61, 1, 100, 0, 1, 26, 100, 1, 2, 64, 75, 76, 0, 0, 0, 0, 0, 226, 94, 215, 1, 0, 0, 0, 0, 50, 0, 0>>,
        program: program,
        accounts: Enum.map(accounts, fn %{key: k, writable?: w} -> %Solana.Account{key: B58.decode58(k), writable?: w, signer?: false} end)
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
    end

    test "parse_with_lookup/3 resolves lookup table keys for versioned tx (with Mox expect)" do
      lookup_key = :crypto.strong_rand_bytes(32)
      lookup_table_pubkey = :crypto.strong_rand_bytes(32)
      # Set up Mox for Rpc
      Solana.RPC.Mock
      |> Mox.expect(:send, fn _rpc_url, req ->
        assert {"getAccountInfo", [_, %{"encoding" => "base64"}]} = req

        data = :crypto.strong_rand_bytes(32) <> :crypto.strong_rand_bytes(8) <> <<1::little-32>> <> lookup_key
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
      {parsed, extras} = Transaction.parse_with_lookup(bin, "mock-url", &Solana.RPC.Mock.send/2)
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
        writable_indexes: [1], # lookup_key2
        readonly_indexes: [0]  # lookup_key1
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
      dbg(bin)
      assert {parsed, extras} = Transaction.parse(bin)
      # Compression checks
      accounts = Keyword.get(extras, :accounts)
      static_accounts = Enum.take(accounts, 3) # payer, program, (maybe more if not in ALT)
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
        readonly_indexes: [0, 1] # shared_key, alt1_key
      }
      lookup2 = %Transaction.AddressTableLookup{
        account_key: alt2_pubkey,
        writable_indexes: [],
        readonly_indexes: [0, 1] # shared_key, alt2_key
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
end
