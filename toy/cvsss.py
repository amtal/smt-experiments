#!/usr/bin/env python
if __name__ == '__main__':
    # Quick usage example:
    import cvsss    # Access     # Access                # Impact
                    # Vector     # Complexity Auth       # C/I/A
    from cvsss import Loc,Adj,Net, Hi,Med,Lo, Mul,Sin,Non, N,P,C

    AV,AC,Au,C,I,A,score1 = cvsss.base('CVE-2014-1337') # network vuln /w auth
    problem = {'knowns': AV != Loc and Au == Sin, 'leetness': score1>=90}

    AV,AC,Au,C,I,A,score2 = cvsss.base('CVE-2014-1338') # open-ended vuln
    problem.update({'sanity': score2 > score1, 'max-leetness': score2 >= 90})

    soln = cvsss.solve(problem)
    if soln:
        print('CVSS leetness: %s, %s' % (soln.eval(score1), soln.eval(score2)))

# SOLIPSISTIC PUBLIC LICENSE
# Version 1, April 2013
# 
# Copyright (C) 2014
# 
# Everyone is permitted to copy and distribute verbatim copies of
# this license document. Modified copies of this document are 
# permitted provided that they denounce BOTH the original AND their
# copy as mere sense data with no verifiable cause outside the mind.
# 
#                     SOLIPSISTIC PUBLIC LICENSE
#   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
# 
# 0. The term 'work' refers to the false sense-data distributed
#    with this license.
# 1. The term 'you' refers to the only being who verifiably exists.
# 2. The term 'author' refers to the set of delusions whereby you
#    incorrectly assign external agency to the work.
# 3. You may copy, modify and distribute the work without restrictions
#    provided that you do not believe the author exists, and provided
#    that you affirm publicly when referring to the work, or when
#    questioned or interrogated by beings who putatively exist, that
#    the work does not exist. 
"""Z3 optimization of CVSS v2.0

Because serious problems require serious tools. (And a serious license, which
if you're a real whitehat you'll follow to the letter. Violators will be
reported, and their CISSP/CEH revoked!)
"""
import re
from z3 import *

def _met(metric, vals, weights):
    sort, [lo,med,hi] = EnumSort(metric, vals.split())

    def maker(name):
        var = Const(name + metric, sort)
        real = If(var==lo, RealVal(weights[0]), 
                If(var==med, RealVal(weights[1]), RealVal(weights[2])))
        return (var, real)

    return maker, lo, med, hi

W = [[0.395, 0.646, 1.000],
     [0.350, 0.610, 0.710], 
     [0.450, 0.560, 0.704], # are these numbers NUMS??
     [0.000, 0.275, 0.660]] # what if they're backdoored!
_fAV, Loc,Adj,Net = _met('AccessVector', 'Local Adjacent Network', W[0])
_fAC, Hi, Med,Lo  = _met('AccessComplexity', 'High Medium Low', W[1])
_fAu, Mul,Sin,Non = _met('AUthentication', 'Multiple Single None', W[2])
_fI,  N,P,C =       _met('', 'None Partial Complete', W[3])

def base(name):
    """CVSS 2.0, June 2007 guide, "formula version 2.10"
    
    Look not under the hood, lest you be disappoined.
    """
    symvars, (AV,AC,Au,C,I,A) = zip(*[f(name + '.' + s) for f,s in zip(
        [_fAV, _fAC, _fAu, _fI, _fI, _fI],
        ['', '', '', 'Confidentiality', 'Integrity', 'Availability']
    )])

    impact = 10.41 * (1 - (1 - C) * (1 - I) * (1 - A))
    exploitability = 20 * AV * AC * Au
    score = ToInt(10 * (0.6 * impact + 0.4 * exploitability - 1.5) *
                         If(impact == 0.0, 0.0, 1.176))
    return symvars + (score,)

def solve(constraints, count_alt=32):
    """Arbitrary metrics for arbitrary goals, today!

    Can be trivially modified to iteratively maximize a cost function during
    alternate solution enumeration.
    
    count_alt: enumerate existance of up to n alternate solutions
    """
    s = Solver()
    [s.assert_and_track(constraints[name], name) for name in constraints]
    soln = s.check()
    if soln == unsat:
        print('[!] no solution, try relaxing constraints: %s' % s.unsat_core())
    elif soln == unknown:
        print('[E] oops! %s' % s.reason_unknown())
    elif soln == sat:
        print('[+] first solution found')
        for v in vectors(s.model()):
            print('\t%s' % v)
        
        if count_alt:
            s.push()
            for n in range(count_alt):
                model = s.model()
                s.add(Or([d() != model[d] for d in model]))
                soln = s.check()
                if soln == unsat: 
                    print('[+] %d alternate solutions available' % n)
                    break
                elif soln == sat:
                    continue
                elif soln == unknown:
                    print('[W] error counting alts: %s' % s.reason_unknown())
                    break
            else:
                print('[+] %d+ alternate solutions available' % count_alt)
            s.pop()
            s.check() # re-generate model for first solution

        return s.model() 

FMT = '\t{name}(AV:{AV}/AC:{AC}/Au:{AU}/C:{C}/I:{I}/A:{A})'
def vectors(model):
    results = [(str(m),model[m]) for m in model if not is_true(model[m])]

    vecs = {}
    for name,val in sorted(results):
        if '.' not in name or len(name) < len('Integrity'):
            continue # probably a custom variable
        name,metric = name.rsplit('.')
        metric,val = [re.sub('[a-z]', '', s) for s in [metric, str(val)]]
        if name not in vecs:
            vecs[name] = {metric:val}
        else:
            vecs[name][metric] = val

    return [FMT.format(name=n, **vecs[n]) for n in sorted(vecs.keys())]
