defmodule RawwaterWeb.ProductView do
  use RawwaterWeb, :html

  alias Rawwater.Products.Product

  import RawwaterWeb.ShopHelpers

  embed_templates "../templates/product_html/*"

  def product_image_filename(%Product{name: name}) do
    "#{name}.jpg"
    |> String.replace(" ", "-")
  end

  def product_image_path(product) do
    "/images/products/#{product_image_filename(product)}"
  end

  def product_thumb_path(product) do
    "/images/products/thumb/#{product_image_filename(product)}"
  end
end
