import hashlib
import base58

from point import Point

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
    return hashlib.new('ripemd160', hashlib.new('sha256', ret).digest()).digest() if hash160 else ret

  def addr(self, net: str, compressed: bool) -> str:
    hash         = self.encode(compressed = compressed, hash160 = True)
    hash_version = { 'main': b'\x00', 'test': b'\x6f' }[net] + hash
    checksum     = hashlib.new('sha256', hashlib.new('sha256', hash_version).digest()).digest()[:4]
    byte_addr    = hash_version + checksum
    return base58.b58encode(byte_addr)

