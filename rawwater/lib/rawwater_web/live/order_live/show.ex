defmodule RawwaterWeb.OrderLive.Show do
  use RawwaterWeb, :live_view

  require Logger, warn: false

  alias Rawwater.Tickets
  alias Rawwater.Products
  alias Rawwater.Minibase
  alias Rawwater.Hellform

  @impl true
  def mount(_params, %{"ticket_id" => ticket_id} = _session, socket) do
    ticket = Tickets.get_ticket_without_database(ticket_id)
    hellform = Hellform.new(ticket.seed)

    {:ok,
     socket
     |> assign(:hellform, hellform)
     |> assign(:current_ticket, ticket)}
  end

  @impl true
  def handle_params(%{"id" => order_id} = _params, _session, socket) do
    with big_ticket <- Tickets.get_ticket(socket.assigns.current_ticket.id),
         db <-
           Minibase.maybe_initialize(
             big_ticket.database,
             socket.assigns.hellform
           ),
         loaded_form = %Hellform{} <-
           Minibase.load_order(db, socket.assigns.hellform, order_id) do
      product = Products.get_product!(loaded_form.product_id)

      {:noreply,
       socket
       |> assign(:hellform, loaded_form)
       |> assign(:product, product)
       |> assign(:title, "ordered #{product.name}")}
    else
      {:error, reason} ->
        Logger.error(inspect(reason))

        {:noreply,
         socket
         |> put_flash(:error, "couldn't load order")
         |> push_navigate(to: Routes.page_path(socket, :dashboard))}

      nil ->
        {:noreply,
         socket
         |> put_flash(:error, "couldn't load order")
         |> push_navigate(to: Routes.page_path(socket, :dashboard))}
    end
  end
end
