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
