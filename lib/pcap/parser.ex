defmodule Pcap.Parser do
  @moduledoc """
  State of the Pcap Parser.

  Keeps track of the current file, parsed blocks, current block being read.
  """

  defstruct file: nil, blocks: [], current: nil

  def new(file), do: %__MODULE__{file: file}
  def file(%__MODULE__{file: file}), do: file
  def blocks(%__MODULE__{blocks: blocks}), do: blocks
  def current(%__MODULE__{current: current}), do: current
  def current(%__MODULE__{} = mod, current), do: %__MODULE__{mod | current: current}
  def flush(%__MODULE__{} = mod), do: %__MODULE__{mod | current: nil}
  def close(%__MODULE__{} = mod), do: %__MODULE__{mod | file: nil}

  def add(%__MODULE__{blocks: blocks} = mod, block) do
    %__MODULE__{mod | blocks: [block | blocks]}
  end
end
