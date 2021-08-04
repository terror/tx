import hashlib
from dataclasses import dataclass
from typing import List

from encode import encode_int, encode_varint
from script import Script
from hash import sha256

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
  # and the locking script associated with the output
  #
  # note: the locking script essentially specifies under what
  # conditions this output can be spent in the future
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

  @property
  def id(self) -> str:
    # returns this transactions ID
    return sha256(sha256(self.encode()))[::-1].hex()

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
      ret += [tx_in.encode(script_override=(sig_idx == i)) for i, tx_in in enumerate(self.tx_ins)]

    ret += [encode_varint(len(self.tx_outs))]
    ret += [tx_out.encode() for tx_out in self.tx_outs]
    ret += [encode_int(self.locktime, 4)]
    ret += [encode_int(1, 4) if sig_idx != -1 else b'']

    return b''.join(ret)
