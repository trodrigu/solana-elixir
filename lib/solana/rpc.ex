defmodule Solana.RPC do
  @moduledoc """
  Functions for dealing with Solana's [JSON-RPC
  API](https://docs.solana.com/developing/clients/jsonrpc-api).
  """
  require Logger

  alias Solana.RPC
  import Solana.Helpers

  @typedoc "Solana JSON-RPC API client."

  @doc """
  Sends the provided requests to the configured Solana RPC endpoint.
  """
  def send(url, requests) do
    Req.new(base_url: url)
    |> Req.post(json: Solana.RPC.Request.encode(requests))
  end

  @doc """
  Sends the provided transactions to the configured RPC endpoint, then confirms them.

  Returns a tuple containing all the transactions in the order they were confirmed, OR
  an error tuple containing the list of all the transactions that were confirmed
  before the error occurred.
  """
  def send_and_confirm(url, tracker, txs, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5_000)
    request_opts = Keyword.take(opts, [:commitment])
    requests = Enum.map(List.wrap(txs), &RPC.Request.send_transaction(&1, request_opts))

    url
    |> RPC.send(requests)
    |> Enum.flat_map(fn
      {:ok, signature} ->
        [signature]

      {:error, %{"data" => %{"logs" => logs}, "message" => message}} ->
        [message | logs]
        |> Enum.join("\n")
        |> Logger.error()

        []

      {:error, error} ->
        Logger.error("error sending transaction: #{inspect(error)}")
        []
    end)
    |> case do
      [] ->
        :error

      signatures ->
        :ok = RPC.Tracker.start_tracking(tracker, signatures, request_opts)
        await_confirmations(signatures, timeout, [])
    end
  end

  defp await_confirmations([], _, confirmed), do: {:ok, confirmed}

  defp await_confirmations(signatures, timeout, done) do
    receive do
      {:ok, confirmed} ->
        MapSet.new(signatures)
        |> MapSet.difference(MapSet.new(confirmed))
        |> MapSet.to_list()
        |> await_confirmations(timeout, List.flatten([done, confirmed]))
    after
      timeout -> {:error, :timeout, done}
    end
  end

  @doc false
  def cluster_url(network) when network in ["devnet", "mainnet-beta", "testnet"] do
    {:ok, "https://api.#{network}.solana.com"}
  end

  def cluster_url("localhost"), do: {:ok, "http://127.0.0.1:8899"}

  def cluster_url(other) when is_binary(other) do
    case URI.parse(other) do
      %{scheme: nil, host: nil} -> {:error, "invalid cluster"}
      _ -> {:ok, other}
    end
  end

  def cluster_url(_), do: {:error, "invalid cluster"}

  defp retry_opts(%{retry_options: retry_options}) do
    Keyword.merge(retry_defaults(), retry_options)
  end

  defp retry_defaults() do
    [max_retries: 10, max_delay: 4_000, should_retry: &should_retry?/1]
  end

  defp should_retry?({:ok, %{status: status}}) when status in 500..599, do: true
  defp should_retry?({:ok, _}), do: false
  defp should_retry?({:error, _}), do: true
end
