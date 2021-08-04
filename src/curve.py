from dataclasses import dataclass

@dataclass
class Curve:
  # secp256k1
  # actual curve used in BITCOIN #btc #shill
  # a = 0, b = 7, p = some large prime
  a: int
  b: int
  p: int

  def new():
    return Curve(
      a = 0x0000000000000000000000000000000000000000000000000000000000000000,
      b = 0x0000000000000000000000000000000000000000000000000000000000000007,
      p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    )
