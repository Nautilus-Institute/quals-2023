defmodule Rawwater.Repo.Migrations.AddDbSizeToTickets do
  use Ecto.Migration

  def change do
    execute(
      """
      ALTER TABLE tickets
      ADD COLUMN db_size bigint
        GENERATED ALWAYS AS (octet_length(database)) STORED;
      """,
      "ALTER TABLE tickets DROP COLUMN db_size;"
    )
  end
end
