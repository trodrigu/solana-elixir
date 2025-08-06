defmodule Solana.KeyMeta do
  @moduledoc """
  Represents metadata for each key included in a transaction.
  """
  defstruct [
    :key,
    writable?: false,
    signer?: false,
    invoked?: false
  ]
end

