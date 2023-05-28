defmodule Rawwater.Repo.Migrations.CreateTickets do
  use Ecto.Migration

  def change do
    create table(:tickets, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :slug, :string, null: false
      add :encrypted, :string, null: false
      add :reset_at, :naive_datetime, null: true
      add :database, :binary, null: true
      add :seed, :bigint, null: false

      timestamps()
    end

    create unique_index(:tickets, [:slug])
  end
end
