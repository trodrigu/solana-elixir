defmodule Solana.Application do
  use Application

  require Logger

  def start(_type, _args) do
    children =
        # Conditionally start Tidewave server for development
        if Mix.env() == :dev and Code.ensure_loaded?(Tidewave) and Code.ensure_loaded?(Bandit) do
          Logger.info("Starting Tidewave server on port 4000 for development")
          [{Bandit, plug: Tidewave, port: 4000}]
        else
          []
        end

    opts = [strategy: :one_for_one, name: MyApp.Supervisor]
    Supervisor.start_link(children, opts)
  end
end