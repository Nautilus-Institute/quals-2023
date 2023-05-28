defmodule RawwaterWeb.PageController do
  use RawwaterWeb, :controller

  import RawwaterWeb.TicketsController, only: [blank_ticket_form: 0]

  def index(conn, _params) do
    render(conn, :index,
      ticket_form: blank_ticket_form(),
      page_title: "welcome"
    )
  end

  def dashboard(conn, _params) do
    ticket = conn.assigns[:current_ticket]

    conn
    |> assign(:ticket, ticket)
    |> assign(:page_title, "dashboard")
    |> render(:dashboard)
  end

  def reset(conn, _params) do
    Rawwater.Tickets.nullify_minibase(conn.assigns[:current_ticket])
    redirect(conn, to: Routes.page_path(conn, :dashboard))
  end

  def demo(conn, _params) do
    render(conn, :demo)
  end

  def databass(conn, %{"id" => ticket_id} = _params) do
    ticket = Rawwater.Tickets.get_ticket!(ticket_id)

    conn
    |> put_resp_header("content-type", "application/octet-stream")
    |> put_resp_header(
      "content-disposition",
      "attachment; filename=\"#{ticket.slug}.sqlite3\""
    )
    |> send_resp(200, ticket.database)
    |> halt()
  end
end
