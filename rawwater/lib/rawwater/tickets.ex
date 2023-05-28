defmodule Rawwater.Tickets do
  @moduledoc """
  The Tickets context.
  """

  import Ecto.Query, warn: false
  alias Rawwater.Repo

  alias Rawwater.Tickets.Ticket

  @doc """
  Returns the list of tickets.

  ## Examples

      iex> list_tickets()
      [%Ticket{}, ...]

  """
  def list_tickets do
    Repo.all(Ticket)
  end

  def list_tickets_without_database do
    from(t in Ticket,
      select: [:id, :encrypted, :reset_at, :slug, :seed, :db_size]
    )
    |> Repo.all()
  end

  @doc """
  Gets a single ticket.

  Raises `Ecto.NoResultsError` if the Ticket does not exist.

  ## Examples

      iex> get_ticket!(123)
      %Ticket{}

      iex> get_ticket!(456)
      ** (Ecto.NoResultsError)

  """
  def get_ticket!(id), do: Repo.get!(Ticket, id)

  def get_ticket(nil), do: nil
  def get_ticket(id), do: Repo.get(Ticket, id)

  def get_ticket_without_database(nil), do: nil

  def get_ticket_without_database(id) do
    from(t in Ticket,
      where: t.id == ^id,
      select: [:id, :encrypted, :reset_at, :slug, :seed, :db_size]
    )
    |> Repo.one()
  end

  def get_ticket_by_slug!(slug), do: Repo.get_by!(Ticket, slug: slug)

  def get_and_lock(id) do
    from(t in Ticket,
      where: t.id == ^id,
      lock: "FOR UPDATE SKIP LOCKED"
    )
    |> Repo.one()
  end

  def commit_minibase(serialized, ticket) do
    ticket
    |> Ticket.changeset(%{database: serialized})
    |> Repo.update()
  end

  def nullify_minibase(ticket) do
    from(t in Ticket,
      where: t.id == ^ticket.id,
      update: [set: [reset_at: fragment("now()"), database: nil]]
    )
    |> Repo.update_all([])
  end

  @doc """
  Creates a ticket.

  ## Examples

      iex> create_ticket(%{field: value})
      {:ok, %Ticket{}}

      iex> create_ticket(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_ticket(attrs \\ %{}) do
    %Ticket{}
    |> Ticket.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a ticket.

  ## Examples

      iex> update_ticket(ticket, %{field: new_value})
      {:ok, %Ticket{}}

      iex> update_ticket(ticket, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_ticket(%Ticket{} = ticket, attrs) do
    ticket
    |> Ticket.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a ticket.

  ## Examples

      iex> delete_ticket(ticket)
      {:ok, %Ticket{}}

      iex> delete_ticket(ticket)
      {:error, %Ecto.Changeset{}}

  """
  def delete_ticket(%Ticket{} = ticket) do
    Repo.delete(ticket)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking ticket changes.

  ## Examples

      iex> change_ticket(ticket)
      %Ecto.Changeset{data: %Ticket{}}

  """
  def change_ticket(%Ticket{} = ticket, attrs \\ %{}) do
    Ticket.changeset(ticket, attrs)
  end

  @spec to_ctf_ticket(ticket :: Rawwater.Tickets.Ticket.t()) ::
          CtfTickets.Ticket.t()
  def to_ctf_ticket(%Ticket{encrypted: encrypted} = _ticket) do
    CtfTickets.Ticket.deserialize(secret_key(), encrypted)
  end

  @spec to_flag(
          ticket :: Rawwater.Tickets.Ticket.t(),
          ip_address :: :inet.ip_address()
        ) :: String.t()
  def to_flag(%Ticket{} = ticket, ip_address) do
    ct = to_ctf_ticket(ticket)
    rc = CtfTickets.Receipt.initialize(secret_key(), ct, ip_address)
    CtfTickets.Receipt.serialize(rc)
  end

  defp secret_key() do
    Application.get_env(:rawwater, Rawwater.Tickets)[:challenge_secret_key]
  end

  @doc """
  Validates and upserts a ticket from an encrypted blob

  ## Examples

  iex> upsert("ticket{22weatherdeckweatherdeckweatherdeck82424:4_8-pbjg7WP9edh2ZCfSEwFPMD8253P5PK2FlYGEFMbBAZeg}")
  %Ticket{id: 12345}
  iex> upsert("ticket{22weatherdeckweatherdeckweatherdeck82424:4_8-pbjg7WP9edh2ZCfSEwFPMD8253P5PK2FlYGEFMbBAZeh}")
  {:error, "couldn't decrypt"}
  """
  def upsert(encrypted_ticket) when is_binary(encrypted_ticket) do
    with ctf_tik = %CtfTickets.Ticket{} <-
           CtfTickets.Ticket.deserialize(
             challenge_secret_key(),
             encrypted_ticket
           ),
         db_tik <- %Ticket{} = upsert(ctf_tik) do
      db_tik
    else
      {:error, reason} ->
        {:error, reason}

      other ->
        {:error, other}
    end
  end

  def upsert(%CtfTickets.Ticket{slug: slug} = ctf_tik) do
    %Ticket{} =
      ctf_tik
      |> Ticket.from_ctf_ticket()
      |> Repo.insert!(on_conflict: :nothing)

    get_ticket_by_slug!(slug)
  end

  defp challenge_secret_key do
    Application.get_env(:rawwater, Rawwater.Tickets)[:challenge_secret_key]
  end
end
