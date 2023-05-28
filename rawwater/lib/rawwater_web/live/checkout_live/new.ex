defmodule RawwaterWeb.CheckoutLive.New do
  use RawwaterWeb, :live_view

  alias Rawwater.Hellform
  alias Rawwater.Products
  alias Rawwater.Tickets
  alias Rawwater.Minibase
  alias Rawwater.Repo

  import RawwaterWeb.PageComponents

  require Logger, warn: false

  @impl true
  def mount(%{"id" => id}, %{"ticket_id" => ticket_id} = _session, socket) do
    with ticket = %Tickets.Ticket{} <-
           Tickets.get_ticket_without_database(ticket_id),
         product = %Products.Product{} <- Products.get_product(id) do
      {:ok,
       socket
       |> assign(:remote_ip, get_connect_info(socket, :peer_data).address)
       |> assign(:current_ticket, ticket)
       |> assign(:product, product)
       |> assign(:page_title, "Buying #{product.name}")
       |> assign(:hellform, Hellform.new(ticket.seed))
       |> assign(:page_number, 1)}
    else
      _ ->
        {:ok,
         socket
         |> put_flash(:error, "couldn't check out")
         |> push_redirect(to: ~p"/")}
    end
  end

  @impl true
  def handle_params(%{"page" => page_number_s} = params, _session, socket) do
    hellform = Hellform.accept_params(socket.assigns.hellform, params)

    page_number =
      case Integer.parse(page_number_s) do
        {n, _rest} -> n
        _other -> 1
      end

    show_page(params, hellform, page_number, socket)
  end

  def handle_params(params, _session, socket) do
    hellform = Hellform.accept_params(socket.assigns.hellform, params)

    page_number = Hellform.first_unhappy_page_number(hellform)

    case page_number do
      nil -> create_order(params, hellform, socket)
      _ -> show_page(params, hellform, page_number, socket)
    end
  end

  defp show_page(_params, hellform, page_number, socket) do
    {page, page_params} = Hellform.page_and_params(hellform, page_number)

    {:noreply,
     socket
     |> assign(:form, page_params |> to_form())
     |> assign(:fields, page)
     |> assign(:hellform, hellform)
     |> assign(:page_number, page_number)
     |> push_event("scroll-top", %{})}
  end

  defp create_order(_params, hellform, socket) do
    if Hellform.valid?(hellform) do
      fr_create_order(hellform, socket)
    else
      Logger.error("hellform wasn't valid")

      {:noreply,
       socket
       |> put_flash(:error, "invalid")
       |> push_navigate(
         to: Routes.product_path(socket, :show, socket.assigns.product.id)
       )}
    end
  end

  defp fr_create_order(hellform, socket) do
    ip = socket.assigns.remote_ip
    ticket_id = socket.assigns.current_ticket.id
    product_id = socket.assigns.product.id

    # start pg tx
    {:ok, reply} =
      Repo.transaction(fn ->
        with big_ticket = %Tickets.Ticket{} <-
               Tickets.get_and_lock(ticket_id),
             db <-
               Minibase.maybe_initialize(
                 big_ticket.database,
                 hellform
               ),

             # place flag in minibase
             flag <- Tickets.to_flag(big_ticket, ip),
             :ok <- Minibase.place_flag(db, flag),

             # run player insert
             {:ok, order_id} <-
               Minibase.save_order(db, product_id, hellform),

             # clear flags from minibase
             :ok <- Minibase.purge_flags(db),

             # write back to pg
             {:ok, serialized} <- Minibase.serialize(db),
             {:ok, _ticket} <- Tickets.commit_minibase(serialized, big_ticket) do
          {:noreply,
           socket
           |> put_flash(:info, "order got")
           |> maybe_put_size_warning(serialized)
           |> push_navigate(to: Routes.order_show_path(socket, :show, order_id))}
        else
          other ->
            Logger.error(["couldn't create order: ", inspect(other)])

            {:noreply,
             socket
             |> put_flash(:error, "couldn't create order")}
        end

        # commit pg tx
      end)

    reply
  end

  defp maybe_put_size_warning(socket, serialized) do
    case Minibase.within_size_warning(serialized) do
      :ok ->
        socket

      {_other, reason} ->
        put_flash(socket, :error, reason)
    end
  end

  @impl true
  def handle_event("save", params, socket) do
    hellform = Hellform.accept_params(socket.assigns.hellform, params)

    # Logger.info(params: params, hellform: hellform)

    # Logger.debug(Hellform.describe(hellform))

    page_number = Hellform.first_unhappy_page_number(hellform)

    case page_number do
      nil -> create_order(params, hellform, socket)
      _ -> show_page(params, hellform, page_number, socket)
    end
  end
end
