defmodule RawwaterWeb.Presence do
  @moduledoc """
  Provides presence tracking to channels and processes.

  See the [`Phoenix.Presence`](https://hexdocs.pm/phoenix/Phoenix.Presence.html)
  docs for more details.
  """
  use Phoenix.Presence,
    otp_app: :rawwater,
    pubsub_server: Rawwater.PubSub

  require Logger

  def init(_opts) do
    {:ok, %{}}
  end

  def handle_metas(
        "demo",
        %{joins: _joins, leaves: _leaves} = _changes,
        presences,
        state
      ) do
    Logger.info(presences)
    present_users = Map.get(presences, "users", [])

    Phoenix.PubSub.local_broadcast(
      Rawwater.PubSub,
      "demo_users",
      {:demo_users, length(present_users)}
    )

    {:ok, state}
  end
end
