import random

from curve import Curve
from generator import Generator
from point import Point
from public_key import PublicKey
from script import Script
from tx import TxIn, TxOut

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
    Script([118, 169, PublicKey.from_point(b_pk).encode(compressed=True, hash160=True), 136, 172])
  )

  # second output will go back to us (change)
  # the diff is the miners fee
  tx_out2 = TxOut.new(
    47500,
    Script([118, 169, PublicKey.from_point(a_pk).encode(compressed=True, hash160=True), 136, 172])
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
