defmodule RawwaterWeb.UserAuth do
  import Plug.Conn

  use RawwaterWeb, :controller

  import Logger, warn: false

  alias Rawwater.Tickets

  def fetch_conn_ticket(conn, _opts) do
    with ticket_id <- get_session(conn, :ticket_id),
         ticket = %Tickets.Ticket{} <-
           Tickets.get_ticket_without_database(ticket_id) do
      conn
      |> assign(:current_ticket, ticket)
    else
      _other -> conn
    end
  end

  def redirect_unless_user_is_authenticated(conn, _opts) do
    unless conn.assigns[:current_ticket] do
      conn
      |> redirect(to: ~p"/")
      |> halt()
    else
      conn
    end
  end

  def redirect_if_user_is_authenticated(conn, _opts) do
    if conn.assigns[:current_ticket] do
      conn
      |> redirect(to: ~p"/dashboard")
      |> halt()
    else
      conn
    end
  end
end
