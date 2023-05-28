defmodule RawwaterWeb.ErrorView do
  use RawwaterWeb, :html

  # If you want to customize a particular status code
  # for a certain format, you may uncomment below.
  # def render("500.html", _assigns) do
  #   "Internal Server Error"
  # end

  embed_templates "../templates/error/*"

  def render(template, _assigns) do
    Phoenix.Controller.status_message_from_template(template)
  end
end
