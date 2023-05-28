defmodule Rawwater.Minibase do
  @moduledoc "The per-ticket database"

  require Logger, warn: false

  alias Rawwater.Hellform
  alias Exqlite.Sqlite3

  @size_warning 524_288
  @size_limit 1_048_576

  @type reason() :: atom() | String.t()

  @spec maybe_initialize(binary(), Hellform.t()) :: Sqlite3.db()
  def maybe_initialize(<<>>, form), do: definitely_initialize(form)
  def maybe_initialize(nil, form), do: definitely_initialize(form)

  def maybe_initialize(data, form) when is_binary(data) do
    with {:ok, db} <- Sqlite3.open(":memory:"),
         :ok <- Sqlite3.deserialize(db, data),
         :ok <- validate_schema(db, form) do
      db
    else
      _other -> definitely_initialize(form)
    end
  end

  defp validate_schema(_db, _form), do: :ok

  defp definitely_initialize(form) do
    {:ok, db} = Sqlite3.open(":memory:")

    :ok =
      exec(db, """
      create table flags
      (id INTEGER PRIMARY KEY,
      flag VARCHAR);
      """)

    :ok =
      exec(db, """
      create table orders
      (id INTEGER PRIMARY KEY,
      product_id VARCHAR,
      #{fields_to_columns(form)}
      );
      """)

    db
  end

  defp fields_to_columns(form) do
    form.field_seqs
    |> Stream.map(fn t -> field_to_column(form.fields[t]) end)
    |> Enum.join(",\n")
  end

  defp field_to_column(field) do
    "\"#{field.tag}\" VARCHAR #{if field.required, do: "NOT NULL"}"
  end

  @spec serialize(Sqlite3.db()) :: {:ok, binary()} | {:error, reason()}
  def serialize(db) do
    with {:ok, serialized} <- Sqlite3.serialize(db),
         :ok <- Sqlite3.close(db),
         :ok <- within_size_limit(serialized) do
      {:ok, serialized}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @spec within_size_warning(binary()) :: :ok | {:warning, reason()}
  def within_size_warning(ser) when byte_size(ser) <= @size_warning, do: :ok

  def within_size_warning(_ser),
    do: {:warning, "database near size limit, consider resetting it"}

  @spec within_size_limit(binary()) :: :ok | {:error, reason()}
  defp within_size_limit(ser) when byte_size(ser) <= @size_limit, do: :ok
  defp within_size_limit(_ser), do: {:error, "database over size limit"}

  @spec place_flag(Sqlite3.db(), binary()) :: :ok | {:error, reason()}
  def place_flag(db, flag) do
    with {:ok, stmt} <-
           prep(db, "INSERT INTO flags (flag) VALUES (?);"),
         :ok <- Sqlite3.bind(db, stmt, [[flag]]),
         {:ok, nil} <- step(db, stmt) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @spec purge_flags(Sqlite3.db()) :: :ok | {:error, reason()}
  def purge_flags(db) do
    exec(db, "DELETE FROM flags;")
  end

  @spec load_order(Sqlite3.db(), Hellform.t(), binary()) ::
          Hellform.t() | nil | {:error, reason()}
  def load_order(db, form, order_id) do
    with {:ok, stmt} <-
           prep(db, """
           SELECT product_id,
           #{fields_to_selectlist(form)}
           FROM orders
           WHERE id = ?
           """),
         :ok <- Sqlite3.bind(db, stmt, [order_id]),
         {:ok, [[product_id | order_row]]} <- fetch(db, stmt) do
      Logger.info(product_id: product_id, row: order_row)
      form = %Hellform{form | product_id: product_id}
      kws = Enum.zip(form.field_seqs, order_row)
      Hellform.accept_params(form, kws)
    else
      {:ok, _other} -> nil
      {:error, reason} -> {:error, reason}
    end
  end

  defp fields_to_selectlist(form) do
    Logger.info(inspect(form))

    form.field_seqs
    |> Enum.map(fn t -> "\"#{t}\"" end)
    |> Enum.join(", ")
  end

  @spec save_order(Sqlite3.db(), binary(), Hellform.t()) ::
          {:ok, integer()} | {:error, reason()}
  def save_order(db, product_id, form) do
    # write sql
    with {:ok, stmt} <-
           prep(db, """
           INSERT INTO orders (
           product_id,
           #{fields_to_insertlist(form)}
           )
           VALUES (
           ?,
           #{fields_to_values(form)}
           )
           RETURNING id;
           """),
         # bind parameters
         :ok <- Sqlite3.bind(db, stmt, [product_id | fields_to_bindlist(form)]),

         # execute
         {:ok, id} <- step(db, stmt) do
      {:ok, id}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp fields_to_insertlist(form) do
    Logger.info(inspect(form))

    form.field_seqs
    |> Enum.map(fn t -> field_to_insertlist(form.fields[t]) end)
    |> tap(fn x -> Logger.info(inspect(x)) end)
    |> List.flatten()
    |> Enum.join(", ")
  end

  defp field_to_insertlist(%Hellform.Field{value: nil} = _field), do: []

  defp field_to_insertlist(%Hellform.Field{tag: t} = _field), do: "\"#{t}\""

  defp fields_to_values(form) do
    form.field_seqs
    |> Enum.map(fn t -> field_to_value(form.fields[t]) end)
    |> List.flatten()
    |> Enum.join(", ")
  end

  defp field_to_value(%Hellform.Field{value: nil} = _field), do: []

  defp field_to_value(%Hellform.Field{value: value, party: true} = _field) do
    "\'#{value}\'"
  end

  defp field_to_value(%Hellform.Field{} = _field) do
    "?"
  end

  defp fields_to_bindlist(form) do
    form.field_seqs
    |> Enum.map(fn t -> field_to_bindlist(form.fields[t]) end)
    |> List.flatten()
    |> tap(fn x -> Logger.info(inspect(x)) end)
  end

  defp field_to_bindlist(%Hellform.Field{value: nil}), do: []
  defp field_to_bindlist(%Hellform.Field{party: true}), do: []
  defp field_to_bindlist(%Hellform.Field{value: v}), do: v

  defp exec(db, sql) do
    Logger.info(sql)
    Sqlite3.execute(db, sql)
  end

  defp prep(db, sql) do
    Logger.info(sql)
    Sqlite3.prepare(db, sql)
  end

  defp step(db, stmt, id \\ nil) do
    case Sqlite3.step(db, stmt) do
      :done ->
        :ok = Sqlite3.release(db, stmt)
        {:ok, id}

      {:error, reason} ->
        _idk = Sqlite3.release(db, stmt)
        {:error, reason}

      :busy ->
        step(db, stmt, id)

      {:row, [id]} ->
        step(db, stmt, id)
    end
  end

  defp fetch(db, stmt, rows \\ []) do
    case Sqlite3.step(db, stmt) do
      :done ->
        :ok = Sqlite3.release(db, stmt)
        {:ok, Enum.reverse(rows)}

      {:error, reason} ->
        _idk = Sqlite3.release(db, stmt)
        {:error, reason}

      :busy ->
        fetch(db, stmt, rows)

      {:row, row} ->
        fetch(db, stmt, [row | rows])
    end
  end
end
