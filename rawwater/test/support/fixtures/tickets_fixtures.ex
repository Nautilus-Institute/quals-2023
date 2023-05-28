defmodule Rawwater.TicketsFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `Rawwater.Tickets` context.
  """

  @doc """
  Generate a unique ticket slug.
  """
  def unique_ticket_slug, do: "some slug#{System.unique_integer([:positive])}"

  @doc """
  Generate a ticket.
  """
  def ticket_fixture(attrs \\ %{}) do
    {:ok, ticket} =
      attrs
      |> Enum.into(%{
        database: "some database",
        encrypted: "some encrypted",
        reset_at: ~N[2023-04-10 02:28:00],
        slug: unique_ticket_slug()
      })
      |> Rawwater.Tickets.create_ticket()

    ticket
  end
end
