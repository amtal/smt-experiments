#!/usr/bin/env python2
from z3 import *

def srand(s):
    return s

def rand(st):
    st = st * 6364136223846793005 + 1
    return st, (st >> 32) & 0x7fffffff

def slug(seed, sz=14):
    """Integer-rand random leak"""
    st = srand(seed)
    acc = []
    for _ in range(sz):
        st,kind = rand(st)
        kind = kind % 3

        base,vals = {
            0:(ord('a'), 26),
            1:(ord('A'), 26),
            2:(ord('0'), 10),
        }[kind]
        st,c = rand(st)
        acc.append(base + (c % vals))
    return acc

def z3_srand(st):
    return Concat(BitVecVal(0, 32), st)

def z3_rand(st):
    st = st * 6364136223846793005 + 1
    return st, Extract(30+32,32, st) # 31 bits out

def z3_slug(seed, sz=14):
    """Integer-rand random leak"""
    st = z3_srand(seed)
    acc = []
    for _ in range(sz):
        st,kind = z3_rand(st)
        kind = Extract(1,0, kind % 3)

        st,c = z3_rand(st)
        
        c = If(kind==0, ord('a') + (c % 26),
               If(kind==1, ord('A') + (c % 26),
                  ord('0') + (c % 10)))
        c = Extract(6,0, c)
        
        acc.append(c)
    return acc

def all_models(s, *query):
    """Add sat results as counterexamples to find more"""
    results = []
    while s.check() == sat:
        mod = s.model()
        print '->', mod
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

if __name__ == '__main__':
    secret = 1
    # can't find sz=5 with 64-bit vars
    # or 7-bit vars... % is still there anyway?
    # neither does reducing seed to the 32 bits it is...
    slug_sz = 5
    leak = slug(srand(secret), slug_sz)
    
    s = Solver()
    seed = BitVec('s', 32)
    sym_leak = z3_slug(seed)
    for sym,val in zip(sym_leak, [BitVecVal(n,7) for n in leak]):
        #print 'unsimp', sym
        sym = simplify(sym) # neat rewrite!
        #print 'simp', sym
        s.add(val == sym)
    #add(seed <= 0xffff) # nah this doesn't do it :\
    print 'Working...'
    #print s.check()
    #print s.assertions()
    print all_models(s, [seed])
    
