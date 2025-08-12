defmodule Solana.Application do
  use Application

  require Logger

  def start(_type, _args) do
    Logger.info("Starting Tidewave server on port 4000 for development")
    children = [{Bandit, plug: Tidewave, port: 4000}]

    opts = [strategy: :one_for_one, name: Solana.TidewaveSupervisor]

    Supervisor.start_link(children, opts)
  end
end
