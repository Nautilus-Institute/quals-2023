defmodule RawwaterWeb.Router do
  use RawwaterWeb, :router

  import RawwaterWeb.UserAuth

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, {RawwaterWeb.LayoutView, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :fetch_conn_ticket
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  defp admin_auth_plug(conn, opts) do
    Plug.BasicAuth.basic_auth(
      conn,
      Application.get_env(:rawwater, :basic_auth)
    )
  end

  pipeline :admin_auth do
    plug :admin_auth_plug
  end

  # scope "/", RawwaterWeb do
  #   # either
  #   pipe_through :browser

  #   get "/demo", PageController, :demo
  # end

  scope "/", RawwaterWeb do
    # unauthenticated
    pipe_through [:browser, :redirect_if_user_is_authenticated]

    get "/", PageController, :index

    post "/login", TicketsController, :create
  end

  scope "/", RawwaterWeb do
    pipe_through [:browser, :redirect_unless_user_is_authenticated]

    get "/dashboard", PageController, :dashboard
    delete "/database", PageController, :reset

    delete "/logout", TicketsController, :logout

    resources "/products", ProductController, only: [:index, :show]

    live_session :checkout do
      live "/checkout/:id", CheckoutLive.New, :new
      live "/orders/:id", OrderLive.Show, :show
    end
  end

  scope "/admin", RawwaterWeb do
    pipe_through [:browser, :admin_auth]

    live "/tickets", TicketLive.Index, :index
    live "/tickets/:id", TicketLive.Show, :show

    get "/database/:id", PageController, :databass

    import Phoenix.LiveDashboard.Router
    live_dashboard "/dashboard", metrics: RawwaterWeb.Telemetry
  end
end
