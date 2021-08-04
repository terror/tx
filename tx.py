#!/usr/bin/python3

import base58
import hashlib
import random
from dataclasses import dataclass
from typing import List, Union

# **** encode.py ****

def encode_int(i, n, e = 'little') -> bytes:
  # https://docs.python.org/3/library/stdtypes.html#int.to_bytes
  # int.to_bytes(length, byteorder, *, signed=False)
  return i.to_bytes(n, e)

def encode_varint(i) -> bytes:
  if i < 0xfd:
    return bytes([i])
  elif i < 0x10000:
    return b'\xfd' + encode_int(i, 2)
  elif i < 0x100000000:
    return b'\xfe' + encode_int(i, 4)
  elif i < 0x10000000000000000:
    return b'\xff' + encode_int(i, 8)
  else:
    raise ValueError(f'integer too large! {i}')

# **** constants.py ****

OP_DUP         = 118
OP_HASH160     = 169
OP_EQUALVERIFY = 136
OP_CHECKSIG    = 172

# **** curve.py ****

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

# **** point.py ****

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

# **** generator.py ****

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

# **** public_key.py ****

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


# **** script.py ****

@dataclass
class Script:
  # https://en.bitcoin.it/wiki/Script
  # OP_DUP         = 118
  # OP_HASH160     = 169
  # OP_EQUALVERIFY = 136
  # OP_CHECKSIG    = 172
  cmds: List[Union[int, bytes]]

  def encode(self):
    ret = []
    for cmd in self.cmds:
      if isinstance(cmd, int):
        ret += [encode_int(cmd, 1)]
      elif isinstance(cmd, bytes):
        assert len(cmd) < 75
        ret += [encode_int(len(cmd), 1), cmd]
    ret = b''.join(ret)
    return encode_varint(len(ret)) + ret

# **** signature.py ****

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

# **** tx.py ****

@dataclass
class TxIn:
  # prev tx / idx are specific output we want to spend
  # must spend entire output (UTXO)
  # can send chunks back to own addr
  prev_index: int
  prev_tx:    bytes
  script_sig: Script = None    # digital signature
  sequence:   int = 0xFFFFFFFF # some high freq trade business

  def new():
    # https://www.blockchain.com/btc-testnet/tx/8501ce07ba5b72d83e32bdf9f2f9a2841314ef3357db80b02bb7b75914e1852f
    # here we already know the previous transaction + index
    return TxIn(
      prev_index = 1,
      prev_tx    = bytes.fromhex('34990f9aa469b81297bac51732d7d8d01c944210'),
    )

  def encode(self, script_override = True) -> bytes:
    # encode this transaction input as bytes
    ret = [
      self.prev_tx[::-1], # why on earth is this flipped?
      encode_int(self.prev_index, 4)
    ]

    if script_override is None:
      ret += [self.script_sig.encode()]
    elif script_override is True:
      ret += [self.prev_tx_script_pk.encode()]
    elif script_override is False:
      ret += [Script([]).encode()]
    else:
      raise ValueError('script_override must be either None | True | False')

    ret += [encode_int(self.sequence, 4)]

    return b''.join(ret)

@dataclass
class TxOut:
  # need to specify amount we want to spend (in satoshis),
  # the amount we want to get back (change, diff is miners fee)
  # and the bitcoin script associated with the output
  amount: int
  s_pk:   Script = None

  def new(amount: int, script: Script = None):
    return TxOut(amount, script)

  def encode(self) -> bytes:
    # encode this transaction output as bytes
    return b''.join(
      [encode_int(self.amount, 8)] +
      [self.s_pk.encode()]
    )

@dataclass
class Tx:
  # represents a transaction. any given TX
  # can have multiple inputs and outputs
  tx_ins:   List[TxIn]
  tx_outs:  List[TxOut]
  version:  int
  locktime: int = 0

  def encode(self, sig_idx = -1) -> bytes:
    # encode this tx as bytes
    # start off with encoded metadata
    ret = [
      encode_int(self.version, 4),
      encode_varint(len(self.tx_ins))
    ]

    if sig_idx == -1:
      ret += [tx_in.encode() for tx_in in self.tx_ins]
    else:
      ret += [tx_in.encode(script_override=(sig_index == i)) for i, tx_in in enumerate(self.tx_ins)]

    ret += [encode_varint(len(self.tx_outs))]
    ret += [tx_out.encode() for tx_out in self.tx_outs]
    ret += [encode_int(self.locktime, 4)]
    ret += [encode_int(1, 4) if sig_index != -1 else b'']

    return b''.join(ret)

# **** __main__.py ****

def main():
  curve     = Curve.new()
  point     = Point.new(curve)
  generator = Generator.new(point)

  a = int.from_bytes(b'first id', 'big') % generator.n
  b = int.from_bytes(b'second id', 'big') % generator.n
  assert 1 <= a < generator.n
  assert 1 <= b < generator.n

  # generate public key by multiplying `point` `seekrit` times
  a_pk = a * point
  b_pk = b * point

  # generate address
  a_addr = PublicKey.from_point(a_pk).addr(net='test', compressed=True)
  b_addr = PublicKey.from_point(b_pk).addr(net='test', compressed=True)

  print('Crypto ID 1:')
  print(f'private key: {a}')
  print(f'public key: {(a_pk.x, a_pk.y)}')
  print(f'address: {a_addr}')

  print('\nCrypto ID 2:')
  print(f'private key: {b}')
  print(f'public key: {(b_pk.x, b_pk.y)}')
  print(f'address: {b_addr}')

  # grab a new transaction input (this has hardcoded values)
  tx_in = TxIn.new()

  # first output will go to the second wallet
  # send out 50k sats
  tx_out1 = TxOut.new(
    50000,
    Script(
      [OP_DUP, OP_HASH160, PublicKey.from_point(b_pk).encode(compressed=True, hash160=True), OP_EQUALVERIFY, OP_CHECKSIG]
    )
  )

  # second output will go back to us (change)
  # the diff is the miners fee
  tx_out2 = TxOut.new(
    47500,
    Script(
      [OP_DUP, OP_HASH160, PublicKey.from_point(a_pk).encode(compressed=True, hash160=True), OP_EQUALVERIFY, OP_CHECKSIG]
    )
  )

  print('\nOutput 1 script:')
  print(tx_out1.s_pk.encode().hex())

  print('\nOutput 2 script:')
  print(tx_out2.s_pk.encode().hex())

  # create the transaction
  tx = Tx(
    version = 1,
    tx_ins  = [tx_in],
    tx_outs = [tx_out1, tx_out2]
  )

if __name__ == '__main__':
  main()
