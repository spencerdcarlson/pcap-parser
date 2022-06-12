defmodule PcapTest do
  use ExUnit.Case
  doctest Pcap

  test "greets the world" do
    assert Pcap.hello() == :world
  end
end
