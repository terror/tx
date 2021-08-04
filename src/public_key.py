import hashlib
import base58

from point import Point
from hash import ripemd160, sha256, b58wchecksum

class PublicKey(Point):
  @classmethod
  def from_point(cls, p: Point):
    return cls(p.curve, p.x, p.y)

  def encode(self, compressed: bool, hash160=False) -> None:
    # return sec bytes encoding of this PK's point
    if compressed:
      ret = (b'\x02', b'\x03')[self.y & 1] + self.x.to_bytes(32, 'big')
    else:
      ret = b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
    return ripemd160(sha256(ret)) if hash160 else ret

  def addr(self, net: str, compressed: bool) -> str:
    # get this public key's associated address
    version = { 'main': b'\x00', 'test': b'\x6f' }[net]
    hash    = version + self.encode(compressed = compressed, hash160 = True)
    return b58wchecksum(hash)

