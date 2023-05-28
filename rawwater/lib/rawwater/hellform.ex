defmodule Rawwater.Hellform do
  # generates a hellish form from a seed

  alias Rawwater.Hellform.Field

  require Logger, warn: false

  defstruct field_seqs: nil, fields: nil, product_id: nil

  @type t :: %__MODULE__{
          field_seqs: list(String.t()),
          fields: %{String.t() => Field.t()},
          product_id: String.t()
        }

  @field_count 100

  @per_page 10

  def mk_state(seed) do
    import Bitwise

    :rand.seed_s(:exsss, [seed >>> 32, seed &&& 0xFFFFFFFF])
  end

  def new(seed) do
    state = mk_state(seed)

    {hot_field_idx_plus, state} = :rand.uniform_s(@field_count, state)
    hot_field_idx = hot_field_idx_plus - 1

    {mine_field_idx_plus, state} = :rand.uniform_s(@field_count, state)

    mine_field_idx =
      case mine_field_idx_plus do
        ^hot_field_idx ->
          Integer.mod(hot_field_idx + 69, @field_count)

        _other ->
          mine_field_idx_plus - 1
      end

    {fields, _state} =
      0..(@field_count - 1)
      |> Enum.flat_map_reduce(state, fn n, state ->
        {field, state} = Field.new(state)

        case n do
          ^hot_field_idx -> {[%Field{field | party: true}], state}
          ^mine_field_idx -> {[%Field{field | landmine: true}], state}
          _other -> {[field], state}
        end
      end)

    seq = Enum.map(fields, fn f -> f.tag end)

    map =
      Enum.reduce(fields, Map.new(), fn f, m ->
        Map.put(m, f.tag, f)
      end)

    %__MODULE__{fields: map, field_seqs: seq}
  end

  def page_seq(%__MODULE__{field_seqs: field_seqs}, page_number) do
    offset = @per_page * (page_number - 1)
    Enum.slice(field_seqs, offset, @per_page)
  end

  def page(form = %__MODULE__{}, page_number) do
    form
    |> page_seq(page_number)
    |> Enum.map(fn k -> form.fields[k] end)
  end

  def page_and_params(form = %__MODULE__{}, page_number) do
    {rseq, params} =
      form
      |> page_seq(page_number)
      |> Enum.reduce({[], %{}}, fn k, {seq, pms} ->
        f = form.fields[k]
        {[f | seq], Map.put(pms, k, f.value)}
      end)

    {Enum.reverse(rseq), params}
  end

  def page_count(form = %__MODULE__{}) do
    form.fields
    |> map_size()
    |> div(@per_page)
    |> ceil()
  end

  def accept_params(form = %__MODULE__{}, params) do
    Enum.reduce(params, form, fn {k, v}, f ->
      update_field(f, f.fields[k], v)
    end)
  end

  defp update_field(form = %__MODULE__{}, nil, _v) do
    form
  end

  defp update_field(form = %__MODULE__{}, _field, "") do
    form
  end

  defp update_field(form = %__MODULE__{}, field = %Field{}, value) do
    # Logger.debug("putting #{value} in #{field.tag} #{field.name}")
    updated_field = %Field{field | value: value}

    updated_form = %__MODULE__{
      form
      | fields: Map.put(form.fields, field.tag, updated_field)
    }

    # Logger.debug(describe(updated_form))
    updated_form
  end

  def valid?(%__MODULE__{fields: fs}) do
    Enum.all?(fs, fn {_k, f} -> Field.valid?(f) end)
  end

  def page_happy?(form = %__MODULE__{}, page_number) do
    page(form, page_number)
    |> Enum.find(fn f -> not Field.happy?(f) end)
    |> is_nil()
  end

  def first_unhappy_page_number(form = %__MODULE__{}) do
    1..page_count(form)
    |> Enum.find(fn pn ->
      not page_happy?(form, pn)
    end)
  end

  def describe(_form = %__MODULE__{field_seqs: seq, fields: fields}) do
    seq
    |> Enum.map(fn k ->
      f = fields[k]
      {f.name, f.value}
    end)
  end
end
