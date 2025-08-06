defmodule Solana.CompiledKeys do
  @moduledoc """
  Holds the compiled key information for v0 transactions.
  Contains a payer and a list of KeyMeta.
  """
  defstruct [
    :payer,
    key_meta: []
  ]
end

