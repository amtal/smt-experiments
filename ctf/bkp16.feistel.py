"""I shouldn't, but am."""
from z3 import *
import click

def py_f(k, m):
    s = (k + m) & 0xFFffFF
    return ((s & 0x1FFF)<<11) | ((s & 0xFFE000)>>13)

def sym_f(k, m):
    s = k + m # right-sized bitvals are auto-truncated
    # Extract is bit-indexed, inclusive
    # Concat is (high, ..., low)
    return Concat(Extract(12,0, s), Extract(23, 13, s))
    # moved 13 bits up and 11 bits down

def enc(lkey, rkey, left, right, f=sym_f):
    for i in range(17):
        left  ^= f(lkey, right)
        right ^= f(rkey, left)
    return left, right

@click.group()
def cli():
    """17 feistel"""
    pass

@cli.command()
def kat():
    """Test whether sym_f matches py_f reference"""
    left, right = enc(0x200003, 0xa15303, 0xdeadbe, 0xefdead, f=py_f)
    print 'py test:', hex(left), hex(right)

    args = [BitVecVal(n,24) for n in [0x200003, 0xa15303, 0xdeadbe, 0xefdead]]
    left, right = enc(*args)
    print 'ciphertext:', hex(simplify(left).as_long()), hex(simplify(right).as_long())
    import sys; sys.exit(0)

@cli.command()
def solve():
    """Full 48-bit solve with one c-p pair"""
    lkey = BitVec('lkey', 24)
    rkey = BitVec('rkey', 24)

    left, right = enc(lkey, rkey, BitVecVal(0, 24), BitVecVal(0, 24))
    print '[x] equation built'

    s = Solver()
    #s.add(simplify(left)  == 0x4f3921) # deadebeef
    #s.add(simplify(right) == 0x74e008) # deadbeef
    s.add(simplify(left)  == 0xeab909) 
    s.add(simplify(right) == 0x387be4) 
    print '[x] constraints added'

    print s.check()
    m = s.model()
    print 'key:', hex(m[lkey].as_long()), hex(m[rkey].as_long())

    # check that ciphertext output matches, for good measure?
    left, right = enc(m[lkey], m[rkey], 0xdeadbe, 0xefdead)
    print 'ciphertext:', hex(simplify(left).as_long()), hex(simplify(right).as_long())


if __name__ == '__main__':
    cli()    
