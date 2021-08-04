import random

from curve import Curve
from generator import Generator
from point import Point
from public_key import PublicKey

def main():
  curve     = Curve.new()
  point     = Point.new(curve)
  generator = Generator.new(point)

  seekrit = random.randrange(1, generator.n)
  assert 1 <= seekrit < generator.n
  print(f'seekrit: {seekrit}') # seekrit exposed

  # generate public key by multiplying `point` `seekrit` times
  pub_key = seekrit * point
  print(f'x: {pub_key.x}\ny: {pub_key.y}')
  print(f'On curve? {pub_key.on_curve(curve)}')

  # generate address
  addr = PublicKey.from_point(pub_key).addr(net='test', compressed=True)
  print(addr)

if __name__ == '__main__':
  main()
