# The Mathematics behind RSA

In RSA, we have two large primes p and q, a modulus N = pq, an encryption exponent e and a decryption exponent d that satisfy ed = 1 mod (p - 1)(q - 1). The public key is the pair (N,e) and the private key is d.

To encrypt a message M, compute

      C = M<sup>e</sup> mod N.

We want to show

      M = C<sup>d</sup> mod N,

i.e., that we can decrypt by raising the ciphertext C to the d power and reducing the result modulo N. But first we must take a slight mathematical detour.

Two positive integers m and n are said to be relatively prime if they have no common factors other than 1. For example, though both 10 and 9 are composite numbers, they are relatively prime, since they have no factor (other than 1) in common.

For a positive integer n, define φ(n) to be the number of integers less than n that are relatively prime with n. For example, φ(12) = 4, since only 11, 7, 5 and 1 are less than 12 and relatively prime to 12, while φ(7) = 6. In fact, for any prime number p we have φ(p) = p - 1.

Suppose the prime factorization of n is given by

      n = p<sub>1</sub><sup>k<sub>1</sub></sup> p<sub>2</sub><sup>k<sub>2</sub></sup> ... p<sub>r</sub><sup>k<sub>r</sub><sup>

Then it can be shown that

      φ(n) = n (1 - 1/p1) (1 - 1/p2) ... (1 - 1/pr)

Note that for the RSA modulus N = pq this result implies

      φ(N) = (p - 1)(q - 1)

The final mathematical result we need is Fermat's Little Theorem. This theorem is usually stated as

Fermat's Little Theorem: If p is prime and p does not divide x, then xp - 1 = 1 mod p
However, a generalization of Fermat's Little Theorem (sometimes known as Euler's Theorem) is more directly applicable to RSA. This theorem states that

Euler's Theorem: If x is relatively prime to n then xφ(n) = 1 mod n
Now back to RSA decryption. We want to show that

      M = Cd = (Me)d = Med mod N.

Recall that ed = 1 mod (p - 1)(q - 1). Also, since N = pq, as noted above, we have

      φ(N) = (p - 1)(q - 1)

and it follows that

      ed = 1 mod φ(N).

Then by the definition of "mod", there is some k such that ed - 1 = kφ(N). We now have

      Med = M(ed - 1) + 1 = M Med - 1 = M Mkφ(N) mod N

Finally, Fermat's Little Theorem (in the form of Euler's Theorem) can be applied to yield the desired result

      Med = M (Mk)φ(N) = M mod N = M.