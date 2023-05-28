defmodule RawwaterWeb.DemoSocket do
  @behaviour Phoenix.Socket.Transport

  require Logger

  defstruct db: nil, stmts: MapSet.new()
  @type t :: %__MODULE__{db: Exqlite.Sqlite3.db(), stmts: MapSet.t(pid())}

  @base_mount_path "/demo_sock"

  @spec base_mount_path :: String.t()
  def base_mount_path, do: @base_mount_path

  @impl true
  def child_spec(_opts) do
    Logger.info("child_spec")

    %{
      id: Task,
      start: {Task, :start_link, [fn -> :ok end]},
      restart: :transient
    }
  end

  @impl true
  def connect(info) do
    Logger.info("connect")
    Logger.info(inspect(info))

    {:ok, %__MODULE__{}}
  end

  @impl true
  def init(args) do
    Logger.info("init")
    Logger.info(inspect(args))

    Phoenix.PubSub.subscribe(Rawwater.PubSub, "demo_users")
    {:ok, _} = RawwaterWeb.Presence.track(self(), "demo", "users", %{})

    case Exqlite.Sqlite3.open(":memory:") do
      {:ok, db} -> {:ok, %__MODULE__{db: db}}
      {:error, reason} -> {:error, "exqlite error: #{inspect(reason)}"}
    end
  end

  @impl true
  def handle_in(
        {sql, [opcode: :text]},
        %__MODULE__{db: db, stmts: stmts} = state
      ) do
    Logger.info(sql)

    {:ok, worker} = process_statement(sql, db)

    {:reply, :ok, {:text, "ack #{inspect(worker)}"},
     %__MODULE__{state | db: db, stmts: MapSet.put(stmts, worker)}}
  end

  def handle_in(other, state) do
    Logger.error("unexpected message #{inspect(other)}")
    {:ok, state}
  end

  @impl true
  def handle_info({:result, res}, state) do
    {:push, {:text, inspect(res)}, state}
  end

  def handle_info(:done, state) do
    {:push, {:text, "done"}, state}
  end

  def handle_info({:prepare_error, reason}, state) do
    {:push, {:text, "prepare error: #{inspect(reason)}"}, state}
  end

  def handle_info({:demo_users, count}, state) do
    {:push, {:text, "current demo users: #{count}"}, state}
  end

  def handle_info({:EXIT, pid, reason}, %__MODULE__{stmts: stmts} = state) do
    Logger.info("got exit from #{inspect(pid)} 'cause #{inspect(reason)}")

    unless MapSet.member?(stmts, pid) do
      Logger.info("no idea about that pid tho")
      {:ok, state}
    else
      {:push, {:text, "exited #{inspect(pid)}"},
       %__MODULE__{state | stmts: MapSet.delete(stmts, pid)}}
    end
  end

  def handle_info(unknown, state) do
    Logger.info(
      "handle_info got #{inspect(unknown)} with state #{inspect(state)}"
    )

    {:ok, state}
  end

  @impl true
  def terminate(reason, _state) do
    Logger.debug("terminate #{inspect(reason)}")
    :ok
  end

  defp process_statement(sql, db) do
    it_me = self()

    worker =
      spawn_link(fn ->
        case Exqlite.Sqlite3.prepare(db, sql) do
          {:ok, stmt} ->
            step(it_me, db, stmt)

          {:error, reason} ->
            send(it_me, {:prepare_error, reason})
        end
      end)

    {:ok, worker}
  end

  defp step(it_me, db, stmt) do
    case Exqlite.Sqlite3.step(db, stmt) do
      :done ->
        Exqlite.Sqlite3.release(db, stmt)
        send(it_me, :done)

      :busy ->
        step(it_me, db, stmt)

      {:row, row} ->
        send(it_me, {:result, row})
        step(it_me, db, stmt)

      {:error, reason} ->
        Exqlite.Sqlite3.release(db, stmt)
        send(it_me, {:step_error, reason})
    end
  end
end
