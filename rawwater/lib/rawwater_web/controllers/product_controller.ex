defmodule RawwaterWeb.ProductController do
  use RawwaterWeb, :controller

  alias Rawwater.Products

  def index(conn, _params) do
    products = Products.list_products()
    render(conn, :index, products: products, page_title: "product list")
  end

  def show(conn, %{"id" => id}) do
    product = Products.get_product!(id)
    render(conn, :show, product: product, page_title: product.name)
  end
end
