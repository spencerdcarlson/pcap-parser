defmodule Pcap.Blocks.Common do
  @moduledoc """
  Common PCAP Block
  """

  defstruct type: nil, length: nil, eob: nil, body: nil

  @header_bytes 8
  @static_bytes 12

  def new, do: :eof

  @doc """
  Create new Common Block
  The length includes all bytes in the entire block
    4 bytes - Blocks Type
    4 bytes - Blocks Total Length
    variable length bits - Body
    4 bytes - Blocks Total Length
  End of Block (EOB) is number of bytes from the beginning of the body to the end
  of the entire block. So Total length - 8 bytes.
  """
  def new(type, length), do: %__MODULE__{type: type, length: length, eob: length - @header_bytes}
  def body(%__MODULE__{} = mod, body), do: %__MODULE__{mod | body: body}

  @doc """
  Length of the Common Block Body

  The "Block Total Length" includes the length of every section.
  12 bytes are reserved for:
   * Block Type (4 bytes)
   * Block Total Length (4 bytes)
   * Block Total Length (4 bytes)

  Block total Length - 12 bytes is the number of bytes reserved for the variable length Block Body
  """
  def body_length(%__MODULE__{} = mod) do
    case total_length(mod) do
      bytes when is_number(bytes) and bytes >= @static_bytes -> bytes - @static_bytes
      _ -> 0
    end
  end

  def body_length(_), do: 0

  defp total_length(%__MODULE__{length: length}), do: length
end
