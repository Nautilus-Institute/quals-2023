defmodule Rawwater.TicketsTest do
  use Rawwater.DataCase

  alias Rawwater.Tickets

  describe "tickets" do
    alias Rawwater.Tickets.Ticket

    import Rawwater.TicketsFixtures

    @invalid_attrs %{database: nil, encrypted: nil, reset_at: nil, slug: nil}

    test "list_tickets/0 returns all tickets" do
      ticket = ticket_fixture()
      assert Tickets.list_tickets() == [ticket]
    end

    test "get_ticket!/1 returns the ticket with given id" do
      ticket = ticket_fixture()
      assert Tickets.get_ticket!(ticket.id) == ticket
    end

    test "create_ticket/1 with valid data creates a ticket" do
      valid_attrs = %{
        database: "some database",
        encrypted: "some encrypted",
        reset_at: ~N[2023-04-10 02:28:00],
        slug: "some slug"
      }

      assert {:ok, %Ticket{} = ticket} = Tickets.create_ticket(valid_attrs)
      assert ticket.database == "some database"
      assert ticket.encrypted == "some encrypted"
      assert ticket.reset_at == ~N[2023-04-10 02:28:00]
      assert ticket.slug == "some slug"
    end

    test "create_ticket/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Tickets.create_ticket(@invalid_attrs)
    end

    test "update_ticket/2 with valid data updates the ticket" do
      ticket = ticket_fixture()

      update_attrs = %{
        database: "some updated database",
        encrypted: "some updated encrypted",
        reset_at: ~N[2023-04-11 02:28:00],
        slug: "some updated slug"
      }

      assert {:ok, %Ticket{} = ticket} =
               Tickets.update_ticket(ticket, update_attrs)

      assert ticket.database == "some updated database"
      assert ticket.encrypted == "some updated encrypted"
      assert ticket.reset_at == ~N[2023-04-11 02:28:00]
      assert ticket.slug == "some updated slug"
    end

    test "update_ticket/2 with invalid data returns error changeset" do
      ticket = ticket_fixture()

      assert {:error, %Ecto.Changeset{}} =
               Tickets.update_ticket(ticket, @invalid_attrs)

      assert ticket == Tickets.get_ticket!(ticket.id)
    end

    test "delete_ticket/1 deletes the ticket" do
      ticket = ticket_fixture()
      assert {:ok, %Ticket{}} = Tickets.delete_ticket(ticket)
      assert_raise Ecto.NoResultsError, fn -> Tickets.get_ticket!(ticket.id) end
    end

    test "change_ticket/1 returns a ticket changeset" do
      ticket = ticket_fixture()
      assert %Ecto.Changeset{} = Tickets.change_ticket(ticket)
    end
  end
end
