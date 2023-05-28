defmodule Rawwater.ProductsFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `Rawwater.Products` context.
  """

  @doc """
  Generate a product.
  """
  def product_fixture(attrs \\ %{}) do
    {:ok, product} =
      attrs
      |> Enum.into(%{
        description: "some description",
        name: "some name",
        price: 42
      })
      |> Rawwater.Products.create_product()

    product
  end
end
