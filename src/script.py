from dataclasses import dataclass
from typing import List, Union

from encode import encode_int, encode_varint

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
