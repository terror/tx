import hashlib
import random
from dataclasses import dataclass
from generator import Generator
from point import Point

# basically just two functions:
# sign(sk, msg)        -> Sig
# verify(pk, msg, sig) -> bool

# each sig depends on a sk + message combo
# so people can't just randomly copy it everywhere

# fun video on 2^256 https://www.youtube.com/watch?v=S9JGmA5_unY

@dataclass
class Signature:
  r: int
  s: int

  def encode(self) -> bytes:
    # der encode this signature
    def der(n):
      nb = n.to_bytes(32, 'big').lstrip(b'\x00')
      # prepend 0x00 if first byte >= 0x80??????????????????????????
      if nb[0] >= 0x80:
        nb += b'\x00'
      return nb
    rb      = der(self.r)
    sb      = der(self.s)
    content = b''.join([bytes([0x02, len(rb)]), rb, bytes([0x02, len(sb)]), sb])
    frame   = b''.join([bytes([0x30, len(content)]), content])
    return frame

def sign(seekrit: int, msg: bytes, gen: Generator) -> Signature:
  # note: using rand to generate the sk is bad
  sk = random.randrange(1, gen.n)
  r  = (sk * gen.G).x
  s  = pow(sk, -1, gen.n) * (int.from_bytes(hashlib.new('sha256', hashlib.new('sha256', msg).digest()).digest(), 'big') + seekrit * r) % gen.n
  if s > gen.n / 2:
    s = gen.n - s
  sig = Signature(r, s)
  return sig

def ver(pk: Point, msg: bytes, sig: Signature) -> bool:
  # don't really need this as we're only creating a tx
  # would have to implement this when mining
  pass
