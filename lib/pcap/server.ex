defmodule Pcap.Server do
  @moduledoc """
  Stateful PCAP Next Generation (pcapng) Capture File Parser. Each execution of `Pcap.Server.next/0`
  will return the next block until it returns `:eof` subsequent calls will return `nil`. To close
  the file simply shutdown the process.

  ## Examples
      iex> Pcap.Server.start_link([file: "./priv/one-packet.pcapng"])
      {:ok, #PID<0.242.0>}

      iex> Pcap.Server.next()
      %Pcap.Blocks.Common{
        body: <<77, 60, 43, 26, 1, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 2,
          0, 54, 0, 73, 110, 116, 101, 108, 40, 82, 41, 32, 67, 111, 114, 101, 40, 84,
          77, 41, 32, 105, 57, 45, 57, 56, 56, 48, 72, 32, 67, 80, ...>>,
        eob: 188,
        length: 196,
        type: "\n\r\r\n"
      }
  """

  require Logger
  use GenServer
  alias Pcap.{Blocks.Common, Parser}

  @block_len_bits 32
  @block_type_bytes 4
  @header_bytes 8

  def start_link(options) do
    # Pcap.Server.start_link([file: "./priv/one-packet.pcapng"])
    # Pcap.Server.next()
    # for _ <- 1..4, do: Pcap.Server.next()
    # Pcap.Server |> Process.whereis() |> Process.exit(:normal)
    # https://docs.rs/pcap-parser/0.8.2/pcap_parser/traits/trait.PcapReaderIterator.html
    {opts, init_arg} =
      options
      |> Keyword.put_new(:name, __MODULE__)
      |> Keyword.split([:name, :timeout, :debug, :spawn_opt, :hibernate_after])

    Logger.info("Starting. opts: #{inspect(opts)}, init_arg: #{inspect(init_arg)}")
    GenServer.start_link(__MODULE__, init_arg, opts)
  end

  @impl GenServer
  def init(args) do
    Process.flag(:trap_exit, true)
    Logger.info("Init #{inspect(args)}.")
    {args, _} = Keyword.split(args, [:file])

    state =
      args
      |> Keyword.get(:file)
      |> File.open!([:read, :binary])
      |> Parser.new()

    {:ok, state}
  end

  @impl GenServer
  def terminate(_reason, state) do
    # TODO: Could ensure file closes by using a monitor instead of trapping exits
    state
    |> Parser.file()
    |> File.close()
  end

  # Public API
  def next(server \\ __MODULE__), do: GenServer.call(server, :next)

  # Internal API
  @impl GenServer
  def handle_call(:next, _from, state) do
    parser =
      state
      |> read_header()
      |> read_block()

    {:reply, Parser.current(parser), Parser.flush(parser)}
  end

  defp read_header(%Parser{file: file} = parser) when is_pid(file) do
    # pcapng file spec: https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.txt

    # Attempt to read the next Block Type (32 bits) and Block Total Length (32 bits) (Total 8 bytes)
    # If the result is :eof then we have reached the end of the file.
    # ensure the file is open before attempting to read
    # TODO: Could clean this up with custom {:ok|:error, result} functions
    current =
      with true <- Process.alive?(file),
           <<type::binary-size(@block_type_bytes),
             length::little-unsigned-integer-size(@block_len_bits)>> <-
             parser |> Parser.file() |> IO.binread(@header_bytes) do
        Common.new(type, length)
      else
        false ->
          :closed

        :eof ->
          :eof

        error ->
          Logger.error("Error reading Common Block Header. #{inspect(error)}")
          :badread
      end

    # Set Common block as current
    Parser.current(parser, current)
  end

  defp read_header(parser), do: parser

  defp read_block(%Parser{current: %Common{eob: bytes} = current} = parser) do
    length = current |> Common.body_length()

    <<body::binary-size(length), _length::little-unsigned-integer-size(@block_len_bits)>> =
      parser |> Parser.file() |> IO.binread(bytes)

    # Add body to current block
    block = parser |> Parser.current() |> Common.body(body)

    # Update Current block
    Parser.current(parser, block)
  end

  defp read_block(%Parser{file: file, current: current} = parser)
       when is_pid(file) and current in [:eof, :badread] do
    File.close(file)

    Parser.close(parser)
  end

  defp read_block(parser), do: parser
end
