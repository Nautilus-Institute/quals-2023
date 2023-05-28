defmodule RawwaterWeb.TicketLiveTest do
  use RawwaterWeb.ConnCase

  import Phoenix.LiveViewTest
  import Rawwater.TicketsFixtures

  @create_attrs %{
    database: "some database",
    encrypted: "some encrypted",
    reset_at: %{day: 10, hour: 2, minute: 28, month: 4, year: 2023},
    slug: "some slug"
  }
  @update_attrs %{
    database: "some updated database",
    encrypted: "some updated encrypted",
    reset_at: %{day: 11, hour: 2, minute: 28, month: 4, year: 2023},
    slug: "some updated slug"
  }
  @invalid_attrs %{
    database: nil,
    encrypted: nil,
    reset_at: %{day: 30, hour: 2, minute: 28, month: 2, year: 2023},
    slug: nil
  }

  defp create_ticket(_) do
    ticket = ticket_fixture()
    %{ticket: ticket}
  end

  describe "Index" do
    setup [:create_ticket]

    test "lists all tickets", %{conn: conn, ticket: ticket} do
      {:ok, _index_live, html} =
        live(conn, Routes.ticket_index_path(conn, :index))

      assert html =~ "Listing Tickets"
      assert html =~ ticket.encrypted
    end

    test "saves new ticket", %{conn: conn} do
      {:ok, index_live, _html} =
        live(conn, Routes.ticket_index_path(conn, :index))

      assert index_live |> element("a", "New Ticket") |> render_click() =~
               "New Ticket"

      assert_patch(index_live, Routes.ticket_index_path(conn, :new))

      assert index_live
             |> form("#ticket-form", ticket: @invalid_attrs)
             |> render_change() =~ "is invalid"

      {:ok, _, html} =
        index_live
        |> form("#ticket-form", ticket: @create_attrs)
        |> render_submit()
        |> follow_redirect(conn, Routes.ticket_index_path(conn, :index))

      assert html =~ "Ticket created successfully"
      assert html =~ "some encrypted"
    end

    test "updates ticket in listing", %{conn: conn, ticket: ticket} do
      {:ok, index_live, _html} =
        live(conn, Routes.ticket_index_path(conn, :index))

      assert index_live
             |> element("#ticket-#{ticket.id} a", "Edit")
             |> render_click() =~
               "Edit Ticket"

      assert_patch(index_live, Routes.ticket_index_path(conn, :edit, ticket))

      assert index_live
             |> form("#ticket-form", ticket: @invalid_attrs)
             |> render_change() =~ "is invalid"

      {:ok, _, html} =
        index_live
        |> form("#ticket-form", ticket: @update_attrs)
        |> render_submit()
        |> follow_redirect(conn, Routes.ticket_index_path(conn, :index))

      assert html =~ "Ticket updated successfully"
      assert html =~ "some updated encrypted"
    end

    test "deletes ticket in listing", %{conn: conn, ticket: ticket} do
      {:ok, index_live, _html} =
        live(conn, Routes.ticket_index_path(conn, :index))

      assert index_live
             |> element("#ticket-#{ticket.id} a", "Delete")
             |> render_click()

      refute has_element?(index_live, "#ticket-#{ticket.id}")
    end
  end

  describe "Show" do
    setup [:create_ticket]

    test "displays ticket", %{conn: conn, ticket: ticket} do
      {:ok, _show_live, html} =
        live(conn, Routes.ticket_show_path(conn, :show, ticket))

      assert html =~ "Show Ticket"
      assert html =~ ticket.encrypted
    end

    test "updates ticket within modal", %{conn: conn, ticket: ticket} do
      {:ok, show_live, _html} =
        live(conn, Routes.ticket_show_path(conn, :show, ticket))

      assert show_live |> element("a", "Edit") |> render_click() =~
               "Edit Ticket"

      assert_patch(show_live, Routes.ticket_show_path(conn, :edit, ticket))

      assert show_live
             |> form("#ticket-form", ticket: @invalid_attrs)
             |> render_change() =~ "is invalid"

      {:ok, _, html} =
        show_live
        |> form("#ticket-form", ticket: @update_attrs)
        |> render_submit()
        |> follow_redirect(conn, Routes.ticket_show_path(conn, :show, ticket))

      assert html =~ "Ticket updated successfully"
      assert html =~ "some updated encrypted"
    end
  end
end
