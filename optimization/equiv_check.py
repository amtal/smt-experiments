#!/usr/bin/env python2
"""Example of verifying that an optimization is equivalent to original.

This is a refactored-for-clarity snippet from an 0ctf 2017 OneTimePad2 attempt
that went down the wrong (way, way wrong) path.

A common technique while reversing crypto code is to rewrite it for clarity, or
using higher-level primitives you think you've recognized. Introducing bugs at
this stage *hurts*, so at minimum you want to spot check equivalence with a
known answer test (KAT). 

This is pretty effective for a lot of crypto primitives where a single test
will provide good branch coverage, but what if that's not the case?

Well, if you're implementing it in Z3, checking equivalence is trivial and
often cheap.
"""
import z3

def main():
    compare(full_func, optimized_func)
    compare(full_func, lambda a,b:optimized_func(a,b,4))

def compare(f_a, f_b, KAT1=False):
    slv = z3.Solver()
    ## symbolic KAT for all possible values!
    _a = z3.BitVec('a', 128)
    _b = z3.BitVec('b', 128)
    _c = z3.BitVec('c', 128)

    if KAT1: # simplified check for single KAT 
        # KAT generated by simplified.py impl, which was tested vs default impl
        a = 2168252808459182800200373529733108733
        b = 201077186217280107761657580377677060119
        c = 251477512235544897549723629970801765199
        a,b,c = [z3.BitVecVal(n, 128) for n in [a,b,c]]

        slv.add(a == _a)
        slv.add(b == _b)
        slv.assert_and_track(c == _c, 'good_alg_impl')

    ## check equality of two functions
    slv.add(f_a(_a,_b) == _c)
    slv.assert_and_track(f_b(_a,_b) != _c, 'bug_in_my_optimization')
    print '{0.__name__} != {1.__name__}:'.format(f_a, f_b)
    print 'unsat' if slv.check() == z3.unsat else slv.model()

def full_func(a,b): 
    """Passes 1 KAT against reference, probably correct"""
    zero = z3.BitVecVal(0, 128)

    full_acc = zero

    for i in range(127, -1, -1):
        if i == 127:
            # last carry is lost due to the way they wrote loop
            carry = zero
        elif True:
            carry = z3.If(z3.Extract(127, 127, full_acc)==1,
                            z3.BitVecVal(0x87, 128),
                            zero)
        
        inj_a = z3.If(z3.Extract(i, i, b)==1, a, 0)
        
        full_acc <<= 1
        full_acc ^= inj_a
        full_acc ^= carry
        
    return z3.simplify(full_acc)

def optimized_func(a,b, unaffected_bits=5): 
    """Optimization that ignores a complex carry operation for most of the
    loop. If the optimization only affects the low bits of the output, maybe
    there's some clever way to invert it...
    
    Intuition and pen-and-paper exploration suggested that only the low 8 bits
    depend on the carry bit. Curiously, Z3 proves a lower bound of 6 bits!

    A 5 bit limit produces a counterexample:

        [b = 226053144248901864244128050390072677377,
         a = 290588911843058107065384064667062469288,
         c = 194731153667389865904561462587135011251,
         bug_in_my_optimization = True]
    """
    zero = z3.BitVecVal(0, 128)

    full_acc = zero
    min_acc = zero # track simpler state for carry computation

    for i in range(127, -1, -1):
        if i == 127:
            # last carry is lost due to the way they wrote loop
            carry = zero
        elif i > unaffected_bits: # lowest bound proved = 5
            carry = z3.If(z3.Extract(127, 127, min_acc)==1,
                            z3.BitVecVal(0x87, 128),
                            zero)
        else: 
            carry = z3.If(z3.Extract(127, 127, full_acc)==1,
                            z3.BitVecVal(0x87, 128),
                            zero)
        
        inj_a = z3.If(z3.Extract(i, i, b)==1, a, 0)
        
        full_acc <<= 1
        full_acc ^= inj_a
        full_acc ^= carry
        
        min_acc <<= 1
        min_acc ^= inj_a 
        
    return z3.simplify(full_acc)

def actual_func(a,b):
    """Aaaand here's why this was the wrong path to go down. :'( Thought it was
    a bunch of random operations thrown together, meant as Z3 or time-wasting
    fodder - nah."""
    P = z3.BitVecVal(0x100000000000000000000000000000087, 128)
    return (a * b) %  P # <- in GF(2) TODO

if __name__ == '__main__': main()
