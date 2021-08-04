from dataclasses import dataclass
from point import Point

@dataclass
class Generator:
  # some initial point on the curve
  # add this point together `N` times to
  # generate a public key
  G: Point
  n: int

  def new(point: Point):
    return Generator(
      G = point,
      n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    )
