import z3
import click

@click.group()
def cli():
    """Exploring a 64bit variant of Bob Jenkins' public domain PRNG

    256 bits of internal state
    """
    pass


@cli.command()
def seed():
    """Random seed"""
    import os, struct
    seed = os.urandom(32)
    FMT = 'a == 0x%x, b == 0x%x, c == 0x%x, d = 0x%d'
    print FMT % struct.unpack('QQQQ', seed)


@cli.command()
@click.argument('op')
@click.argument('count', type=click.INT)
@click.option('--lowbits', type=click.INT, 
        help='Reverse based on LSbs of outputs')
@click.option('-v', '--verbose', count=True, help='tl;dr')
def recover(op, count, lowbits, verbose):
    """State recovery from full output"""
    print '[x] load'
    assert count > 0
    a,b,c,d = st = raninit()

    slv = z3.Solver()
    if verbose: z3.set_param(verbose=10) # print tactics as they're applied
    qs = []
    for i in range(count):
        st,out = ranval(st)
        q = z3.BitVec('q%d'%i, 64)
        slv.add(q == out)
        qs.append(q)
    print '[x] ranval iterations'

    if op=='forward':
        if 0:
            # actual state should be 256 mixed bits due to urandom input
            slv.add(a == 1337, b == 1338, c == 0xbeef, d == 0xdead)
        else:
            slv.add(a == 0x7ceb42733f66b473, b == 0x6b44d35a1f639f60, 
                    c == 0xead7949879cb1623, d == 0x9565653158395212103)
    elif op=='reverse': 
        if 0:
            #slv.add(a == 1337, b == 1338, c == 0xbeef, d == 0xdead)
            slv.add(qs[4] == 6515443366520749290)
            slv.add(qs[3] == 15987207590933627957)
            slv.add(qs[2] == 12139072452908344637)
            slv.add(qs[1] == 17436066800174026442)
            slv.add(qs[0] == 400248179)
        else:
            # TODO generate these instead of copy-pasting lol
            q_vals = [
                6985222460364329868, 10544382677601029469,
                15438707448398115707, 16064190778767654258, 282720256118252307,
                18290176035634059913, 1825954770632955011,
                11019636138942255088, 9429738565397434521, 6583642313917153474,
                11369469077210583108, 590431549771258938, 291271844620794731,
                4009518777267550210, 8383857281027991160
            ] # 15 of 'em, considering that output is directly from 1/4th of
              # state that should be plenty...
            q_vals.reverse() 
            for i in range(count):
                slv.add(qs[i] == q_vals[i])
    print '[x] constraints'

    sat_ret = slv.check()
    print '[x] result:', sat_ret
    if sat_ret == z3.sat:
        print(slv.model())
    elif sat_ret == z3.unsat:
        print(slv.unsat_core())


def raninit():
    """
    Initialization is a 256-bit seed + 30x ranval() iterations.

    Can thus ignore it and focus on state recovery at any point, not the
    original seed.
    """
    return z3.BitVecs('a b c d', 64)

def ranval_py(st):
    a,b,c,d = st
    e = a - z3.RotateLeft(b, 7)
    a = b ^ z3.RotateLeft(c, 13)
    b = c + z3.RotateLeft(d, 37)
    c = d + e
    d = e + a
    return (a,b,c,d), d

def rot(x,k): return (x<<k)|(x>>(64-k))

def ranval(st):
    a,b,c,d = st
    e = a - z3.RotateLeft(b, 7)
    a = b ^ z3.RotateLeft(c, 13)
    b = c + z3.RotateLeft(d, 37)
    c = d + e
    d = e + a
    return (a,b,c,d), d


if __name__ == '__main__':
    cli()
