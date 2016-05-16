#!/usr/bin/env python2
from z3 import *

def to_bits(length, N):
  return [BitVecVal(int(i), 1) for i in bin(N)[2:].zfill(length)]

def from_bits(N):
  return int("".join(str(i) for i in N), 2)

CRC_POLY = to_bits(65, (2**64) + 0xeff67c77d13835f7)
CONST = to_bits(64, 0xabaddeadbeef1dea)
assert len(CONST) == 64

def crc(mesg):
  mesg += CONST
  shift = 0
  while shift < len(mesg) - 64:
    #print '#', mesg[shift:shift+64], bin(simplify(Concat(*mesg)).as_long())
    cur_bit = mesg[shift]
    for i in range(65):
      #print '##', simplify(mesg[shift+i]^CRC_POLY[i])
      temp = simplify(If(1 == cur_bit, mesg[shift + i] ^ CRC_POLY[i], mesg[shift + i]))
      mesg[shift + i] = temp
    shift += 1
  #print mesg
  print '[x] crc eqn ready'
  #return Concat(*mesg[-64:])
  return mesg[-64:]

INNER = to_bits(8, 0x36) * 8
OUTER = to_bits(8, 0x5c) * 8

def xor(x, y):
  return [g ^ h for (g, h) in zip(x, y)]

def hmac(h, key, mesg):
  eqn = h(xor(key, OUTER) + h(xor(key, INNER) + mesg))
  print '[x] hmac eqn ready'
  return eqn


PLAIN_1 = "zupe zecret"
PLAIN_2 = "BKPCTF"

def str_to_bits(s):
  return [b for i in s for b in to_bits(8, ord(i))]

def bits_to_hex(b):
  return hex(simplify(b).as_long()).rstrip('L')

if __name__ == "__main__":
  if 0: # KATs
      assert '0xf9029866e9509dd3' == bits_to_hex(crc(str_to_bits(PLAIN_1)))
      assert '0x7313c64212534e79' == bits_to_hex(crc(str_to_bits(PLAIN_2)))
      print '[x] CRC KAT passed'
      KEY = to_bits(8, 0x41) * 8
      assert '0x91ce0a86f492262a' == bits_to_hex(Concat(*hmac(crc, KEY, str_to_bits(PLAIN_1))))
      print '[x] HMAC KAT passed'

  #with open("key.txt") as f:
  #  KEY = to_bits(64, int(f.read().strip("\n"), 16))
  KEY = [BitVec('k%d' % n,1) for n in range(64)]
  s = Solver()
  s.add(simplify(Concat(*hmac(crc, KEY, str_to_bits(PLAIN_1)))) == 0xa57d43a032feb286)
  print '[x] constraints set'
  print s.check()
  print s.model()

  print PLAIN_1, "=>", bits_to_hex(hmac(crc, KEY, str_to_bits(PLAIN_1)))
  print "BKPCTF{" + bits_to_hex(hmac(crc, KEY, str_to_bits(PLAIN_2))) + "}"

