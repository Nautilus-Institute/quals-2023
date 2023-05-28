[
  import_deps: [:ecto, :phoenix],
  inputs: [
    "*.{ex,exs, heex}",
    "priv/*/seeds.exs",
    "{config,lib,test}/**/*.{ex,exs}"
  ],
  subdirectories: ["priv/*/migrations"],
  plugins: [Phoenix.LiveView.HTMLFormatter],
  line_length: 80
]
