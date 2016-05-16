#!/usr/bin/env python2
"""Finding fixpoints...
> Vm0 -> Vm0w
> wd2 -> d2Qy
> QyU -> UXlV
[x] base64 = Vm0wd2QyU
> Vm0 -> Vm0w
> wd2 -> d2Qy
> QyU -> UXlV
[x] base64url = Vm0wd2QyU
> JJFEM -> JJFEMRKN
> RKNKJ -> KJFU4S2K
[x] base32 = JJFEMRKNKJ
> 6P83G -> 6P83GCQ7
> CQ78D -> 8D8JEE24
[x] base32hex = 6P83GCQ78D
Done.            
"""
import fractions
import math
from z3 import * # aargh FIXME can I avoid cluttering scope?

_r = lambda s:range(ord(s[0]), ord(s[1]) + 1) # inclusive range
ALPHABETS = [
    ('base64',    64, _r('AZ') + _r('az') + _r('09') + map(ord, '+/')),
    ('base64url', 64, _r('AZ') + _r('az') + _r('09') + map(ord, '-_')),
    ## ^ minor changes, same fixpoint \/ major changes, way different!
    ('base32',    32, _r('AZ') + _r('27')),
    ('base32hex', 32, _r('09') + _r('AV')),
    ## base58 needs Ints + is significantly larger than predecessors + breaks
    ## my input-output calculations due to power-of-2 assumptions.
    #('base58buttcoin', 58,
    # '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'),
]
for _, sz, vals in ALPHABETS: assert len(vals) == sz


def main():
    print 'Finding fixpoints...'
    for name,_,vals in ALPHABETS:
        fp = search(vals, verbose=1)
        print '[x]', name, '=', fp
    print 'Done.'


def search(alphabet, verbose=0):
    """Solve for unknowns to get a fully-known fixpoint

    verbose: 1=lookbusy, 2=AST dumps
    """

    # trying to generalize to 58...
    if len(alphabet) == 58:
        assert (lcm(256, len(alphabet))/256) % 1.0 == 0
        w = lcm(256, len(alphabet))/256 * 8
    else:
        w = lcm(8, width_in_bits(len(alphabet))) # min byte resynch boundary
    inputs = [BitVec('x%d' % n, w) for n in range(w / 8)]
    outputs = [BitVec('y%d' % n, w) for n in
               range(w / width_in_bits(len(alphabet)))]
    
    lut = z3_build_lut(alphabet)
    
    s = Solver()
    # because I'm using wide variables rather than manually dealing with
    # casts, I need to enforce ASCII sanity constraints:
    for var in inputs + outputs:
        s.add(var < 256)

    # encode function constraint
    for sym_var, out_var in zip(outputs,
                                rfc4648_gen(inputs, lut, len(alphabet))):
        s.add(sym_var == out_var)

    # all permanent constraints set, start solving
    fix_in = []
    fix_out = []
    while (len(fix_out) - len(fix_in))*8 < w:
        # after this loop is done, there's no more unknowns left;
        # fixpoint is deterministic from tehre if it exists at all
        
        s.push()
        # add known values
        knowns = fix_out[len(fix_in):]
        for v_in, known_val in zip(inputs, knowns):
            s.add(v_in == known_val)
        # add unknown in-out constraints
        for v_in, v_out in zip(inputs[len(knowns):], outputs):
            s.add(v_in == v_out)
        
        [[chunk_in, chunk_out]] = all_models(s, inputs, outputs) # assert unique
        if verbose:
            print '>', to_string(chunk_in), '->', to_string(chunk_out)

        fix_in += chunk_in
        fix_out += chunk_out
        s.pop()

    if verbose>1: # print interesting bits?
        print s.assertions()
        #print s.to_smt2()

    return to_string(fix_in)


USE_BV = True
# BitVecs support cheap shift and bit operations
# BitVecs multiplies and friends are expensive
# Ints don't support bit operations and are arbitrary-width
# Arrays are for sparse big stuff like RAM
#
# for now, implement via BitVecs for speed (try Ints later for fun)
def rfc4648_gen(inputs, alph, alph_size):
    """RFC 4648 encoding, generalized.

    alph_size: must be passed since Arrays are unbounded

    KATs are a pain in the ass when using Z3 types, and supporting both
    them and Python types is kind of a PITA. Dropping KATs for now!
    """
    n = 0
    for in_val in inputs: # big endian
        if USE_BV:
            n <<= 8
            n |= in_val
        else:
            n *= 256
            n += in_val
        
    # FIXME: lift out?
    in_bits = lcm(8, width_in_bits(alph_size))
    out_bits = in_bits / width_in_bits(alph_size) * 8
    in_bytes, out_bytes = in_bits / 8, out_bits / 8
    assert in_bits == in_bytes * 8 and out_bits == out_bytes * 8 # sanity
    assert len(inputs) == in_bytes
    
    outputs = []
    for _ in range(out_bytes):
        if USE_BV:
            index = n & (alph_size-1)
            n >>= width_in_bits(alph_size)
        else:
            index = n % alph_size
            n /= alph_size
        outputs.append(Select(alph, index))
    return reversed(outputs) # big endian


## bit math

def lcm(a,b):
    """Least common multiple"""
    return abs(a * b) / fractions.gcd(a,b)

def width_in_bits(n):
    w = math.log(n) / math.log(2)
    assert w % 1.0 == 0 # <-- cross fingers here
    return int(w)


## Z3 wrangling

def to_string(ms):
    """Partial type coersion"""
    assert all([is_bv(m) for m in ms]) 
    return ''.join([chr(m.as_long()) for m in ms])

def all_models(s, *query):
    """Add sat results as counterexamples to find more"""
    results = []
    while s.check() == sat:
        mod = s.model()
        one_result = []
        constraint = []
        for varset in query:
            ms = []
            for var in varset:
                ms.append(mod[var])
                constraint.append(var != mod[var])
            one_result.append(ms)
        results.append(one_result)
        s.add(Or(*constraint))
    return results

def z3_build_lut(values):
    """Array theory cannon on a fixed-size LUT bird.

    Choosing widest necessary integer to avoid figuring out promotion.
    """
    w = lcm(8, width_in_bits(len(values))) # min byte resynch boundary
    lut = Array('t', BitVecSort(w), BitVecSort(w))
    for index,val in enumerate(values):
        lut = Store(lut, index, val) # <- this don't look good when printed
    return lut


if __name__ == '__main__':
    main()
