defmodule Rawwater.Repo do
  use Ecto.Repo,
    otp_app: :rawwater,
    adapter: Ecto.Adapters.Postgres
end
