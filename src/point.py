from dataclasses import dataclass
from math import gcd
from curve import Curve

@dataclass
class Point:
  # represents a point on the elliptic curve
  # overrides: add, rmul
  curve: Curve
  x:     int
  y:     int

  def __add__(self, o):
    INF = Point(None, None, None)

    if self == INF:
      return o
    if o == INF:
      return self
    if self.x == o.x and self.y != o.y:
      return INF

    if self.x == o.x:
      m = (3 * self.x ** 2 + self.curve.a) * pow(2 * self.y, -1, self.curve.p)
    else:
      m = (self.y - o.y) * pow(self.x - o.x, -1, self.curve.p)

    rx = (m ** 2 - self.x - o.x) % self.curve.p
    ry = (-(m * (rx - self.x) + self.y)) % self.curve.p

    return Point(
      self.curve,
      rx,
      ry
    )

  def __rmul__(self, k: int):
    # needs to be fast since we're adding points
    # some absurd amount of times
    r, a = Point(None, None, None), self
    while k:
      if k & 1:
        r += a
      a += a
      k >>= 1
    return r

  def new(curve: Curve):
    return Point(
      curve,
      x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

  def on_curve(self, curve: Curve) -> bool:
    return (self.y ** 2 - self.x ** 3 - 7) % curve.p == 0
