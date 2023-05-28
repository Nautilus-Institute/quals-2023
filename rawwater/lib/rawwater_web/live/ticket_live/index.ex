defmodule RawwaterWeb.TicketLive.Index do
  use RawwaterWeb, :live_view

  alias Rawwater.Tickets
  #  alias Rawwater.Tickets.Ticket

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, :tickets, list_tickets())}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "Listing Tickets")
    |> assign(:ticket, nil)
  end

  defp list_tickets do
    Tickets.list_tickets_without_database()
  end
end
