defmodule Pcap do
  @moduledoc """
  Parse a PCAP Next Generation (pcapng) Capture File.
  https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html
  """
  alias Pcap.{Blocks.Common, Parser}

  @block_len_bits 32
  @block_type_bytes 4
  @header_bytes 8

  def parse(path \\ "./priv/one-packet.pcapng") do
    parser =
      path
      |> File.open!([:read, :binary])
      |> Parser.new()
      |> read()

    parser
    |> Parser.file()
    |> File.close()

    Parser.blocks(parser)
  end

  defp read(%Parser{current: :eof} = parser), do: parser

  defp read(%Parser{} = parser) do
    parser
    |> read_header()
    |> read_block()
    |> read()
  end

  defp read_header(%Parser{} = parser) do
    # pcapng file spec: https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.txt

    # Attempt to read the next Block Type (32 bits) and Block Total Length (32 bits) (Total 8 bytes)
    # If the result is :eof then we have reached the end of the file.
    current =
      case parser |> Parser.file() |> IO.binread(@header_bytes) do
        <<type::binary-size(@block_type_bytes),
          length::little-unsigned-integer-size(@block_len_bits)>> ->
          Common.new(type, length)

        :eof ->
          :eof

        _ ->
          raise "Error reading Common Block Header"
      end

    # Add Common block to state
    Parser.current(parser, current)
  end

  defp read_block(%Parser{current: %Common{eob: bytes} = current} = parser) do
    length = current |> Common.body_length()

    <<body::binary-size(length), _length::little-unsigned-integer-size(@block_len_bits)>> =
      parser |> Parser.file() |> IO.binread(bytes)

    # Add body to current block
    block = parser |> Parser.current() |> Common.body(body)

    # Add current block to list of blocks and flush current block
    parser
    |> Parser.add(block)
    |> Parser.flush()
  end

  defp read_block(%Parser{current: :eof} = parser), do: parser
end
