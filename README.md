# Lessons Learned

Fixed-cost problems like brute forcing CRCs, `srand(time(0))`, etc:

* You don't need to limit yourself to Z3 if you use SMT-LIB or a frontend like
  Haskell's sbv. But, Z3 is pretty good nowadays.
* If you know a fast way to solve the problem, an SMT solution will be slower.

Some CTF challenges and optimization problems:

* "Hail mary" solver runs for large, complex problems probably won't complete.
* Implementing a problem with an SMT solver may be much faster than actually
  understanding the problem. Understanding can come later.

Toy problems:

* Problems with a "complexity" variable you can adjust are good candidates for
  SMT. You can adjust it high enough that solutions are non-trivial, but
  complete quickly.
* SMT is okay for exploring messy search problems you understand poorly.
