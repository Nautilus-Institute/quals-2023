defmodule RawwaterWeb.ShopHelpers do
  @moduledoc """
  Conveniences for building shop pages
  """

  use Phoenix.Component

  @doc """
  Currency with style
  """

  def price(pennies_price) do
    assigns = %{
      dollars_part: floor(pennies_price / 100),
      cents_part:
        pennies_price
        |> Integer.mod(100)
        |> Integer.to_string()
        |> String.pad_trailing(2, "0")
    }

    ~H"""
    <span class="price">
      <span class="currency">$</span><span class="dollars"><%= @dollars_part %></span><span class="decimal">.</span><span class="cents"><%= @cents_part %></span>
    </span>
    """
  end
end
