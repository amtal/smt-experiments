"""SQLite function for doing BPP optimization using Z3

May your sense of wonder 
Be forever tempered by horror
"""
from pprint import pprint
import z3

class BPP:
    """Aggregate values then pack them into a maximum.
    
    Override constrain(self) with additional constraints built from
    self.var[name] vars. Oh and override show() I guess, except it's
    not just show but also returns the solution you want to blacklist
    in further searches.
    """
    def __init__(self):
        self._classes = {}
        self._all_items = []
        self.var = {}
        self.sol = z3.Solver()
        self.max_value = 1e6 # TODO unhardcode this

    def _step(self, item_class, item_name, item_value):
        """Called while iterating over input cursor"""
        # optimization: don't complicate with overlarge items lol
        if item_value > self.max_value:
            return

        item = self._var(item_name)

        if item_class in self._classes:
            self._classes[item_class].append(item)
        else:
            self._classes[item_class] = [item]

        self._all_items.append(item * int(item_value))

    def _final(self):
        """Finished iteration"""
        # symvar for total number of items 
        item_acc = [self.var[k] for k in self.var]
        [self.sol.add(self.var[k] >= 0) for k in self.var] # <- w/o this things get weird :)
        symvar = self._var('_sum_items')
        self.sol.add(symvar == z3.Sum(*item_acc))
        # symvar (and upper bound) on total value
        symvar = self._var('_sum_value')
        self.sol.add(symvar == z3.Sum(*self._all_items))
        self.sol.add(symvar <= z3.IntVal(int(self.max_value)))
        # class count constraints, to make it interesting
        [self.sol.add(self._var(key.lower()) == z3.Sum(*self._classes[key]))
            for key in self._classes]

        # custom constraints
        self.constrain(self.sol, self.var)
        print '[x] constraints built'

        # solve
        soln_num = 0
        while 1:
            self.sol.push()
            if self.sol.check() == z3.unsat:
                print 'unsat at:', self.sol.unsat_core()
                return 0
            else:
                mod = self.sol.model()
                ship_acc = self.show(mod)

                # hill climbing constraint goes here
                self.sol.pop()
                self.sol.assert_and_track(z3.Or([d() != ship_acc[d] for d in ship_acc]), 
                        'soln%d' % soln_num) 
                soln_num += 1
        
        return 1

    def _var(self, name):
        """Caches Z3 variables for ghetto constraint addition"""
        name = name.encode('utf-8')
        var = z3.Int(name)
        self.var[name] = var
        return var

    def constrain(self, sol, var):
        raise NotImplemented

    def show(mod):
        """Render solution in a quasi-readable way
        
        And also build a list of interesting values out of it, cuz why not."""
        return mod

    @classmethod
    def factory(cls):
        return cls(), cls._step, cls._final
