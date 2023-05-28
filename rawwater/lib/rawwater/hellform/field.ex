defmodule Rawwater.Hellform.Field do
  defstruct name: nil,
            required: false,
            value: nil,
            party: false,
            landmine: false,
            tag: nil

  @type t :: %__MODULE__{
          name: String.t(),
          required: boolean,
          value: nil | String.t(),
          party: boolean,
          landmine: boolean,
          tag: String.t()
        }

  @require_probability 0.5

  @address_desc ~w{home work vacation travel tavern hotel office parents billing primary secondary partner spouse}
  @address_parts ~w{street chōme number postcode zip4 city state prefecture county commonwealth district municipality phone fax modem tty}

  @name_desc ~w{your partner spouse least_favorite_child cat dog snake}
  @name_parts ~w{first_name last_name family_name given_name surname house_name honorific}

  @payment ~w{pan cvv iban cardholder verif cash tax_id}

  @vehicle_desc ~w{personal kids partner spouse rental weekend winter}
  @vehicle_parts ~w{vin license color make model year title trim_color trim_level front_wheel_diameter front_wheel_width rear_wheel_diameter rear_wheel_width front_tire_width front_tire_aspect front_tire_diameter rear_tire_width rear_tire_aspect rear_tire_diameter}

  @tax_desc ~w{work personal partner side_gig foreign british canadian dutch cutout fake_identity stolen_identity cosplay clown}
  @tax_parts ~w{ordinary_business_income net_rental_real_estate_income other_net_rental_income guaranteed_payments_for_services guaranteed_payments_for_capital total_guaranteed_payments interest_income ordinary_dividends qualified_dividends dividend_equivalents royalties net_short-term_capital_gain net_long-term_capital_gain collectibles_gain unrecaptured_section_1250_gain net_section_1231_gain other_income section_179_deduction other_deduction self-employment_earnings credits schedule_k3 tax-exempt_income_and_nondeductible_expenses distributions}

  @gizmo_desc ~w{personal work defcon burner travel}
  @gizmo_parts ~w{make model year serial imei iccid wifi_mac bluetooth_mac seid eid meid color}

  @tag_len 8

  @spec new(:rand.state()) :: {__MODULE__.t(), :rand.state()}
  def new(state) do
    {n, state} = :rand.uniform_s(state)

    cond do
      n > 0.999 -> taargus(state)
      n > 0.9 -> payment(state)
      n > 0.7 -> vehicle(state)
      n > 0.6 -> address(state)
      n > 0.5 -> name(state)
      n > 0.4 -> gizmo(state)
      true -> tax(state)
    end
  end

  defp taargus(state) do
    normal(["taargüs"], ["taargüs"], state)
  end

  defp payment(state) do
    normal(@name_desc, @payment, state)
  end

  defp vehicle(state) do
    normal(@vehicle_desc, @vehicle_parts, state)
  end

  defp address(state) do
    normal(@address_desc, @address_parts, state)
  end

  defp name(state) do
    normal(@name_desc, @name_parts, state)
  end

  defp gizmo(state) do
    normal(@gizmo_desc, @gizmo_parts, state)
  end

  defp tax(state) do
    normal(@tax_desc, @tax_parts, state)
  end

  defp normal(desc, parts, state) do
    {desc, state} = pick(desc, state)
    {part, state} = pick(parts, state)
    {reqd, state} = :rand.uniform_s(state)

    {tag_b, state} = :rand.bytes_s(@tag_len, state)
    tag = Base.url_encode64(tag_b, padding: false)

    {%__MODULE__{
       name: "#{desc}_#{part}",
       required: reqd < @require_probability,
       tag: tag
     }, state}
  end

  def part_to_human(part) do
    part
    |> String.replace("_", " ")
  end

  defp pick(coll, state) do
    count = length(coll)

    {idx, new_state} = :rand.uniform_s(count, state)
    picked = Enum.at(coll, idx - 1)

    {picked, new_state}
  end

  def happy?(_field = %__MODULE__{required: false}), do: true
  def happy?(_field = %__MODULE__{value: v}) when not is_nil(v), do: true
  def happy?(_field), do: false

  def valid?(_field = %__MODULE__{landmine: false}), do: true

  def valid?(_field = %__MODULE__{landmine: true, value: v}) do
    not String.contains?(v, "'")
  end
end
