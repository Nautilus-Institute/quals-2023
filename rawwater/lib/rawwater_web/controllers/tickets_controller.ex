defmodule RawwaterWeb.TicketsController do
  use RawwaterWeb, :controller

  alias Rawwater.Tickets

  require Logger

  def create(conn, %{"encrypted_ticket" => enc} = _params) do
    case enc |> String.trim() |> Tickets.upsert() do
      %Tickets.Ticket{id: ticket_id} ->
        conn
        |> put_session(:ticket_id, ticket_id)
        |> redirect(to: ~p"/")

      reason ->
        Logger.error(
          "failed to decrypt ticket #{inspect(enc)} because #{inspect(reason)}"
        )

        conn
        |> put_flash(:error, inspect(reason))
        |> redirect(to: ~p"/")
    end
  end

  def logout(conn, _params) do
    conn
    |> delete_session(:ticket_id)
    |> redirect(to: ~p"/")
  end

  def blank_ticket_form() do
    %{"encrypted_ticket" => nil} |> Phoenix.Component.to_form()
  end
end
