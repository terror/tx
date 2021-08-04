from dataclasses import dataclass
from script import Script

@dataclass
class TxIn:
  # prev tx / idx are specific output we want to spend
  # must spend entire output (UTXO)
  # can send chunks back to own addr
  prev_index: int
  prev_tx:    bytes
  script_sig: Script = None    # digital sig
  sequence:   int = 0xFFFFFFFF # some high freq trade business

  def new():
    return TxIn(
      prev_index = 1,
      prev_tx    = bytes.fromhex('46325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2'),
    )

@dataclass
class TxOut:
  amount: int # in satoshis
  s_pk:   Script = None

  def new(amount: int):
    return TxOut(amount)
