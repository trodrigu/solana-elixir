defmodule Solana.TransactionDebug do
  @moduledoc """
  Debug utilities for Solana.Transaction
  """
  
  alias Solana.{Transaction, Account, CompactArray, Instruction}
  
  @doc """
  Debug the transaction encoding process and print each component
  """
  def debug_transaction(tx = %Transaction{}) do
    with {:ok, ixs} <- Transaction.check_instructions(List.flatten(tx.instructions)),
         accounts = compile_accounts(ixs, tx.payer),
         true <- signers_match?(accounts, tx.signers) do
      
      # Print header information
      header = create_header(accounts)
      header_binary = :binary.list_to_bin(header)
      
      IO.puts("\n=== TRANSACTION DEBUG INFO ===")
      IO.puts("Header values: #{inspect(header)}")
      IO.puts("Header bytes: <<#{:binary.bin_to_list(header_binary) |> Enum.join(", ")}>>\n")
      
      # Print accounts information
      account_keys = Enum.map(accounts, & &1.key)
      IO.puts("Number of accounts: #{length(account_keys)}")
      
      account_keys_binary = :binary.list_to_bin(account_keys)
      IO.puts("Accounts section: <<#{:binary.bin_to_list(account_keys_binary) |> Enum.join(", ")}>>\n")
      
      # Print blockhash
      blockhash_binary = 
        if is_binary(tx.blockhash) and byte_size(tx.blockhash) == 32 do
          tx.blockhash
        else
          case B58.decode58(tx.blockhash) do
            {:ok, decoded} -> decoded
            _ -> raise "Invalid blockhash format"
          end
        end
      
      IO.puts("Blockhash bytes: <<#{:binary.bin_to_list(blockhash_binary) |> Enum.join(", ")}>>\n")
      
      # Print instructions
      instructions_encoded = encode_instructions(ixs, accounts)
      
      # Convert instructions to binary for display
      instructions_binary = 
        instructions_encoded
        |> CompactArray.to_iolist()
        |> :erlang.list_to_binary()
      
      IO.puts("Instructions section: <<#{:binary.bin_to_list(instructions_binary) |> Enum.join(", ")}>>\n")
      
      # Print instruction data specifically
      instruction_data = 
        ixs
        |> List.first()
        |> Map.get(:data)
        |> case do
          nil -> <<>>
          data -> data
        end
      
      IO.puts("Instruction data: <<#{:binary.bin_to_list(instruction_data) |> Enum.join(", ")}>>\n")
      
      # Create the message using the standard method
      standard_message = encode_message(accounts, blockhash_binary, ixs)
      IO.puts("Standard message bytes: <<#{:binary.bin_to_list(standard_message) |> Enum.join(", ")}>>\n")
      
      # Create the message with fixed header encoding
      fixed_message = encode_message_fixed(accounts, blockhash_binary, ixs)
      IO.puts("Fixed message bytes: <<#{:binary.bin_to_list(fixed_message) |> Enum.join(", ")}>>\n")
      
      # Sign the message
      signatures =
        tx.signers
        |> reorder_signers(accounts)
        |> Enum.map(&sign(&1, fixed_message))
      
      signatures_binary = :binary.list_to_bin(signatures)
      IO.puts("Signatures: <<#{:binary.bin_to_list(signatures_binary) |> Enum.join(", ")}>>\n")
      
      # Create the full transaction with fixed encoding
      signature_count = <<length(signatures)>>
      full_transaction = :binary.list_to_bin([signature_count, signatures_binary, fixed_message])
      
      IO.puts("Complete fixed transaction: <<#{:binary.bin_to_list(full_transaction) |> Enum.join(", ")}>>\n")
      IO.puts("=== END DEBUG INFO ===\n")
      
      {:ok, full_transaction}
    else
      error -> error
    end
  end
  
  # Fixed message encoding that matches TypeScript
  defp encode_message_fixed(accounts, blockhash, ixs) do
    # Convert header to exactly 3 bytes without CompactArray encoding
    [num_sigs, num_readonly_signed, num_readonly_unsigned] = create_header(accounts)
    header = <<num_sigs, num_readonly_signed, num_readonly_unsigned>>
    
    # Encode account keys without CompactArray
    account_keys = Enum.map(accounts, & &1.key)
    account_count = <<length(account_keys)>>
    account_data = :binary.list_to_bin(account_keys)
    
    # Encode instructions
    instructions_encoded = encode_instructions(ixs, accounts)
    instructions_binary = CompactArray.to_iolist(instructions_encoded) |> :binary.list_to_bin()
    
    # Combine everything
    :binary.list_to_bin([header, account_count, account_data, blockhash, instructions_binary])
  end
  
  # Standard message encoding from the original module
  defp encode_message(accounts, blockhash, ixs) do
    [
      create_header(accounts),
      CompactArray.to_iolist(Enum.map(accounts, & &1.key)),
      blockhash,
      CompactArray.to_iolist(encode_instructions(ixs, accounts))
    ]
    |> :binary.list_to_bin()
  end
  
  # The following functions are copied from Solana.Transaction
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
end
