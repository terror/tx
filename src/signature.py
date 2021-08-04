from dataclasses import dataclass

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

def sign(seekrit: int, msg: bytes) -> Signature:
  pass

def ver(pk: Point, msg: bytes, sig: Signature) -> bool:
  pass
