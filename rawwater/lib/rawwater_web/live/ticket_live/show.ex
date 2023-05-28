defmodule RawwaterWeb.TicketLive.Show do
  use RawwaterWeb, :live_view

  alias Rawwater.Tickets

  @impl true
  def mount(_params, _session, socket) do
    {:ok, socket}
  end

  @impl true
  def handle_params(%{"id" => id}, _, socket) do
    {:noreply,
     socket
     |> assign(:page_title, page_title(socket.assigns.live_action))
     |> assign(:ticket, Tickets.get_ticket_without_database(id))}
  end

  @impl true
  def handle_event("delete_database", _params, socket) do
    tickie = socket.assigns.ticket
    Tickets.nullify_minibase(tickie)

    {:noreply,
     socket
     |> assign(:ticket, Tickets.get_ticket_without_database(tickie.id))
     |> put_flash(:info, "reset the database")}
  end

  defp page_title(:show), do: "Show Ticket"
end
