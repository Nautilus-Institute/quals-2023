defmodule RawwaterWeb.PageComponents do
  use Phoenix.Component

  attr :page_number, :integer, required: true
  attr :page_count, :integer, required: true

  def page_widget(assigns) do
    ~H"""
    <%= if @page_number > 1 do %>
      <p class="page_label">
        Page <%= @page_number %> of <%= @page_count %>
      </p>

      <ol class="page_picker">
        <%= for n <- 1..@page_count do %>
          <%= if @page_number == n do %>
            <li><span class="non_page"><%= n %></span></li>
          <% else %>
            <li><.link patch={"?page=#{n}"}><%= n %></.link></li>
          <% end %>
        <% end %>
      </ol>
    <% end %>
    """
  end
end
