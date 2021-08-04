import base58
import hashlib

def ripemd160(x):
  h = hashlib.new('ripemd160')
  h.update(x)
  return h.digest()

def sha256(x):
  return hashlib.sha256(x).digest()

def checksum(x):
  return sha256(sha256(x))[:4]

def b58wchecksum(x):
  return base58.b58encode(x + checksum(x))

def b58(x):
  return base58.b58encode(x)
