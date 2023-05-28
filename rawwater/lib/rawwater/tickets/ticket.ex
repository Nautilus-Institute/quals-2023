defmodule Rawwater.Tickets.Ticket do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "tickets" do
    field :database, :binary
    field :encrypted, :string
    field :reset_at, :naive_datetime
    field :slug, :string
    field :seed, :integer
    field :db_size, :integer

    timestamps()
  end

  @type t :: %__MODULE__{
          id: binary(),
          database: binary(),
          db_size: integer(),
          encrypted: String.t(),
          reset_at: NaiveDateTime.t(),
          slug: String.t(),
          seed: integer(),
          inserted_at: NaiveDateTime.t(),
          updated_at: NaiveDateTime.t()
        }

  def from_ctf_ticket(%CtfTickets.Ticket{
        slug: slug,
        seed: seed,
        serialized: serialized
      }) do
    %Rawwater.Tickets.Ticket{
      slug: slug,
      seed: rem(seed, 9_223_372_036_854_775_807),
      encrypted: serialized
    }
  end

  @doc false
  def changeset(ticket, attrs) do
    ticket
    |> cast(attrs, [:slug, :encrypted, :reset_at, :database, :seed])
    |> validate_required([:slug, :encrypted, :seed])
    |> unique_constraint(:slug)
  end
end
