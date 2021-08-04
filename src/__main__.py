import random

from curve import Curve
from generator import Generator
from point import Point
from public_key import PublicKey

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

  print(PublicKey.from_point(a_pk).encode(compressed=True, hash160=True).hex())

  print('\nCrypto ID 2:')
  print(f'private key: {b}')
  print(f'public key: {(b_pk.x, b_pk.y)}')
  print(f'address: {b_addr}')

if __name__ == '__main__':
  main()
