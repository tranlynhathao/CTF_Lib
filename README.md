# CTF_Lib

A comprehensive Python library for solving cryptography challenges in Capture The Flag (CTF) competitions. This library provides implementations of common cryptographic attacks, number theory algorithms, lattice reduction techniques, and various utilities essential for CTF cryptography challenges.

## Overview

CTF_Lib is designed to be a one-stop solution for cryptography CTF challenges. It integrates seamlessly with SageMath, providing high-performance implementations of cryptographic attacks and mathematical algorithms. The library includes both pure Python implementations and optimized C++ extensions for computationally intensive operations.

## Features

- **RSA Attacks**: Multi-prime RSA decryption, Coppersmith attacks
- **Elliptic Curve Cryptography**: ECDLP attacks, invalid curve attacks, ECDSA nonce reuse
- **Lattice-Based Cryptography**: Lattice reduction, approximate GCD, SVP-based inequality solving
- **Symmetric Cipher Attacks**: AES padding oracle, CBC forgery, GCM nonce reuse
- **Number Theory**: Extended Euclidean algorithm, CRT, factorization methods
- **Random Number Generation**: Python random state recovery, Mersenne Twister attacks
- **Linear Algebra**: GF(2) equation solving, bit vector operations
- **Algorithmic Tools**: 2-SAT solver, maximum flow, matroid intersection

## Installation

### Prerequisites

Before installing CTF_Lib, you must install the following dependencies:

1. **SageMath** (version 10.6 or higher)
   - Download from [https://www.sagemath.org/](https://www.sagemath.org/)
   - Or install via package manager: `apt-get install sagemath` (Debian/Ubuntu)

2. **flint** - Fast Library for Number Theory
   - GitHub: [https://github.com/flintlib/flint](https://github.com/flintlib/flint)
   - Follow installation instructions in the repository

3. **flatter** - Fast lattice reduction tool
   - GitHub: [https://github.com/keeganryan/flatter](https://github.com/keeganryan/flatter)
   - Build and install according to repository instructions

4. **msolve** - Polynomial system solver
   - GitHub: [https://github.com/algebraic-solving/msolve](https://github.com/algebraic-solving/msolve)
   - Follow installation instructions in the repository

5. **cuso** - Additional cryptographic utilities
   - GitHub: [https://github.com/keeganryan/cuso](https://github.com/keeganryan/cuso)
   - Install as per repository instructions

### Installing CTF_Lib

```bash
git clone https://github.com/tranlynhathao/CTF_Lib.git
cd CTF_Lib/
pip install .
```

The installation process will compile C++ extensions using pybind11. Ensure you have a C++ compiler with C++26 support and the necessary build tools installed.

## Quick Start

After installation, you can import CTF_Library and start using its functions:

```python
# Method 1: Direct import from specific modules (recommended)
from CTF_Library.Cryptography.RSA.RSA_decrypt import RSA_decrypt
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from math import prod

# Example: RSA decryption with multiple primes
primes = [getPrime(512) for _ in range(3)]
n = prod(primes)
e = 65537
m = bytes_to_long(b"Hello, CTF!")
c = pow(m, e, n)

# Decrypt
decrypted = RSA_decrypt(primes, e, c)
print(long_to_bytes(decrypted[0]))
```

**Note:** The package name is `CTF_Library` (not `CTF_Lib`). While `from CTF_Library import *` may work, direct imports from specific modules are recommended to avoid potential issues with compiled extensions during import.

## Module Documentation

### RSA Cryptography

#### RSA_decrypt

Decrypts RSA ciphertext when you have the prime factors.

```python
from CTF_Library.Cryptography.RSA.RSA_decrypt import RSA_decrypt
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Given: primes, public exponent e, and ciphertext
primes = [p1, p2, p3]  # List of prime factors
e = 65537
ciphertext = 123456789  # Encrypted message

# Decrypt (returns all possible plaintexts)
plaintexts = RSA_decrypt(primes, e, ciphertext)
for pt in plaintexts:
    print(long_to_bytes(pt))
```

**Parameters:**

- `primes`: List of prime factors of the modulus
- `e`: Public exponent
- `enc`: Encrypted message (integer)

**Returns:** List of all possible plaintexts (as integers)

### Elliptic Curve Cryptography

#### ECDLP_invalid_curve_attack

Performs an invalid curve attack on ECDLP when the oracle doesn't verify curve membership.

```python
from CTF_Library.Cryptography.EllipticCurve.ECDLP_invalid_curve_attack import ECDLP_invalid_curve_attack

# Given: prime p, curve parameter a, and oracle function
p = 2**256 - 2**32 - 977
a = -3

def oracle(x, y):
    # Oracle that multiplies point by secret scalar without checking curve membership
    # Returns (x', y') = s * (x, y)
    return multiply_by_secret(x, y)

# Perform attack
r, m = ECDLP_invalid_curve_attack(
    p=p,
    a=a,
    multiply_by_secret=oracle,
    required_modulus_size=256,  # Required bit size for recovery
    curve_count=5  # Number of curves to try
)

# Secret s = r mod m
print(f"Secret modulo: {m}")
print(f"Remainder: {r}")
```

**Parameters:**

- `p`: Prime modulus
- `a`: Curve parameter a (Weierstrass form: y^2 = x^3 + ax + b)
- `multiply_by_secret`: Function that takes (x, y) and returns s*(x, y)
- `required_modulus_size`: Minimum bit size of modulus needed
- `curve_count`: Number of curves to try (default: 1)
- `threshold`: Ignore factors below this threshold (default: 2^40)

**Returns:** Tuple (r, m) where secret s = r mod m

#### ECDSA_nonce_reuse_attack

Recovers the private key when the same nonce is used in multiple ECDSA signatures.

```python
from CTF_Library.Cryptography.EllipticCurve.ECDSA_nonce_reuse_attack import ECDSA_nonce_reuse_attack

# Given: Two signatures (r0, s0), (r1, s1) with same nonce
# Message hashes: h0, h1
# Curve order: n

r0, s0 = signature0
r1, s1 = signature1
h0 = bytes_to_long(hashlib.sha256(message0).digest())
h1 = bytes_to_long(hashlib.sha256(message1).digest())
n = curve_order  # Order of the generator point

private_key, nonce = ECDSA_nonce_reuse_attack(n, h0, r0, s0, h1, r1, s1)
print(f"Private key: {private_key}")
print(f"Nonce: {nonce}")
```

**Parameters:**

- `n`: Order of the generator point
- `h0`, `h1`: Message hashes (integers)
- `r0`, `s0`: First signature components
- `r1`, `s1`: Second signature components

**Returns:** Tuple (private_key, nonce)

### Coppersmith Attacks

#### coppersmith_univariate

Finds small roots of univariate polynomials modulo composite numbers.

```python
from CTF_Library.Cryptography.Coppersmith.coppersmith import coppersmith_univariate

# Example: Find small roots of f(x) mod m
m = 10001
f = [-222, 5000, 10, 1]  # Polynomial coefficients: f(x) = x^3 + 10*x^2 + 5000*x - 222
root_ub = 5  # Upper bound on root size

roots = coppersmith_univariate(m, f, root_ub)
print(f"Found roots: {roots}")
```

**Parameters:**

- `m`: Composite modulus
- `f`: List of polynomial coefficients (monic, highest degree first)
- `root_ub`: Upper bound on root size

**Returns:** List of integer roots r <= root_ub where gcd(f(r), m) != 1

### Lattice Reduction

#### reduce_lattice

Reduces a lattice using the flatter tool for improved performance.

```python
from CTF_Library.Cryptography.Lattice.reduce_lattice import reduce_lattice
from sage.all import matrix

# Create a lattice matrix
mat = matrix(ZZ, [[...], [...], ...])

# Reduce the lattice
reduced = reduce_lattice(mat)
print(f"Reduced lattice:\n{reduced}")
```

**Parameters:**

- `mat`: SageMath matrix representing the lattice

**Returns:** Reduced lattice as SageMath matrix

### Symmetric Cipher Attacks

#### forge_CBC_ciphertext_with_padding_oracle

Forges CBC ciphertext using a padding oracle.

```python
from CTF_Library.Cryptography.SymmetricCiphers.AES.forge_CBC_with_padding_oracle import forge_CBC_ciphertext_with_padding_oracle

def padding_oracle(iv, ciphertext):
    # Returns True if padding is valid, False otherwise
    try:
        decrypt_and_unpad(iv, ciphertext)
        return True
    except:
        return False

# Forge ciphertext for desired plaintext
desired_plaintext = b"admin=1"
forged_iv, forged_ct = forge_CBC_ciphertext_with_padding_oracle(
    plaintext=desired_plaintext,
    padding_oracle=padding_oracle,
    hint=None,  # Optional: (message, iv, ciphertext) tuple
    faulty=False  # Set to True if oracle is faulty
)
```

**Parameters:**

- `plaintext`: Desired plaintext (must be multiple of 16 bytes)
- `padding_oracle`: Function that takes (iv, ciphertext) and returns bool
- `hint`: Optional tuple (message, iv, ciphertext) for optimization
- `faulty`: Whether the oracle is faulty (default: False)
- `pool`: List of byte values to try (default: range(256))

**Returns:** Tuple (iv, ciphertext) or list of tuples if faulty=True

### Number Theory

#### CRT_coefficients

Computes coefficients for Chinese Remainder Theorem representation.

```python
from CTF_Library.Cryptography.NumberTheory.CRT_coefficients import CRT_coefficients

# Given moduli
mods = [m1, m2, m3, ...]

# Compute CRT coefficients
coefs = CRT_coefficients(mods)

# Solution to X = r_i mod m_i is:
# X = sum(coef_i * r_i) mod lcm(mods)
```

**Parameters:**

- `mods`: List of moduli

**Returns:** List of coefficients for CRT representation

#### extended_euclidean

Computes extended GCD for multiple integers.

```python
from CTF_Library.Cryptography.NumberTheory.extended_euclidean import extended_euclidean

# Compute GCD and coefficients
numbers = [a, b, c, d, ...]
gcd_val, coefficients = extended_euclidean(numbers)

# Verify: gcd = sum(coef[i] * numbers[i])
assert gcd_val == sum(c * n for c, n in zip(coefficients, numbers))
```

### Python Random Breaker

#### python_random_breaker

Recovers Python's random state from observed outputs.

```python
from CTF_Library.Cryptography.MersenneTwister.python_random_breaker import python_random_breaker
import random

# Create breaker instance
breaker = python_random_breaker()
breaker.init_twister_after_seeding()

# Observe random outputs
rng = random.Random(secret_seed)
for _ in range(100):
    breaker.setrand_uint(rng.getrandbits(32))
    breaker.setrandbits(17, rng.getrandbits(17))
    breaker.setrandom(rng.random())

# Recover all possible states
states = breaker.recover_all_twister_states()
print(f"Found {len(states)} possible states")

# Recover seeds
seeds = breaker.recover_all_small_integer_seeds_from_state(states[0])
print(f"Possible seeds: {seeds}")
```

**Key Methods:**

- `init_twister_after_seeding()`: Initialize after seeding
- `setrand_uint(x)`: Add observed 32-bit output
- `setrandbits(n, x)`: Add observed n-bit output
- `setrandom(x)`: Add observed float output
- `recover_all_twister_states()`: Recover all possible states
- `recover_all_small_integer_seeds_from_state(state)`: Recover integer seeds

### Linear Algebra over GF(2)

#### linear_equation_solver_GF2

Solves systems of linear equations over GF(2).

```python
from CTF_Library.Cryptography.LinearAlgebra.linear_equation_solver_GF2 import linear_equation_solver_GF2

# Create solver for n variables
solver = linear_equation_solver_GF2(n=100)

# Add equations: equation is a bitmask, output is 0 or 1
solver.add_equation_if_consistent(0b1010, 1)  # x0 + x2 = 1
solver.add_equation_if_consistent(0b1100, 0)  # x1 + x2 = 0

# Solve
assignment, basis = solver.solve()
print(f"Rank: {solver.rank()}")
print(f"Nullity: {solver.nullity()}")
print(f"Number of solutions: {2**solver.nullity()}")

# Get all solutions
all_solutions = solver.all_solutions()
```

**Parameters:**

- `n`: Number of variables

**Methods:**

- `add_equation_if_consistent(equation, output)`: Add equation (returns True if consistent)
- `solve()`: Returns (assignment, basis) tuple
- `all_solutions()`: Returns list of all solutions
- `rank()`: Returns rank of system
- `nullity()`: Returns nullity (number of free variables)

### Algorithms and Data Structures

#### two_sat_solver

Solves 2-SAT problems.

```python
from CTF_Library.Algorithms_And_Data_Structures.two_sat_solver import two_sat_solver

# Create solver for n variables
solver = two_sat_solver(n=10)

# Add clauses: either(u, v) means (u OR v)
solver.either(0, 1)      # x0 OR x1
solver.either(~2, 3)     # NOT x2 OR x3
solver.implies(0, 2)     # x0 -> x2
solver.set_value(5, True)  # x5 = True

# Solve
if solver.solve():
    print("Satisfiable")
    print(solver.value)  # Assignment
else:
    print("Unsatisfiable")
```

#### dinic_maximum_flow

Computes maximum flow using Dinic's algorithm.

```python
from CTF_Library.Algorithms_And_Data_Structures.dinic_maximum_flow import dinic_maximum_flow

# Create flow network
# See flow_network.py for network construction
max_flow = dinic_maximum_flow(network, source, sink)
```

## Common Use Cases

### RSA Challenge with Small Prime Difference

```python
from CTF_Library.Cryptography.Factorization.fermat_factorization import fermat_factorization
from CTF_Library.Cryptography.RSA.RSA_decrypt import RSA_decrypt
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Given: n = p * q where |p - q| is small
n = 12345678901234567890

# Use Fermat factorization (returns one factor)
p = fermat_factorization(n)
q = n // p

# Decrypt
e = 65537
c = 98765432109876543210
m = RSA_decrypt([p, q], e, c)[0]
print(long_to_bytes(m))
```

**Note:** `fermat_factorization` returns one factor. The other factor can be computed as `n // factor`.

### Coppersmith Attack on RSA

```python
from CTF_Library.Cryptography.Coppersmith.coppersmith import coppersmith_univariate
from math import gcd

# Given: n = p * q, and we know p = p0 + x where x is small
n = 12345678901234567890
p0 = 11111111111111111111  # Known part of p
e = 65537
c = 98765432109876543210

# Construct polynomial: f(x) = (p0 + x) mod n
# We want to find x such that gcd(p0 + x, n) != 1
# Note: polynomial coefficients are from highest to lowest degree
# f(x) = x + p0, so coefficients are [p0, 1] (constant term first, then x)
f = [p0 % n, 1]  # f(x) = x + p0 (monic polynomial)
root_ub = 2**20  # x is at most 20 bits

roots = coppersmith_univariate(n, f, root_ub)
for root in roots:
    p_candidate = p0 + root
    if gcd(p_candidate, n) != 1:
        p = gcd(p_candidate, n)
        q = n // p
        m = RSA_decrypt([p, q], e, c)[0]
        print(long_to_bytes(m))
        break
```

**Note:** The polynomial coefficients in `coppersmith_univariate` are ordered from constant term to highest degree term. The polynomial must be monic (leading coefficient = 1).

### Padding Oracle Attack

```python
from CTF_Library.Cryptography.SymmetricCiphers.AES.forge_CBC_with_padding_oracle import forge_CBC_ciphertext_with_padding_oracle
from Crypto.Util.Padding import pad
from pwn import remote

# Connect to server
io = remote("challenge.ctf", 12345)

def padding_oracle(iv, ciphertext):
    io.sendlineafter(b"IV: ", iv.hex().encode())
    io.sendlineafter(b"Ciphertext: ", ciphertext.hex().encode())
    response = io.recvline()
    return b"valid" in response

# Forge admin ciphertext
admin_plaintext = pad(b"admin=1", 16)
forged_iv, forged_ct = forge_CBC_ciphertext_with_padding_oracle(
    plaintext=admin_plaintext,
    padding_oracle=padding_oracle
)

# Send forged ciphertext
io.sendlineafter(b"IV: ", forged_iv.hex().encode())
io.sendlineafter(b"Ciphertext: ", forged_ct.hex().encode())
flag = io.recvline()
print(flag)
```

## Import Patterns

### Recommended: Direct Imports

For reliability and to avoid potential issues with compiled extensions, use direct imports from specific modules:

```python
from CTF_Library.Cryptography.RSA.RSA_decrypt import RSA_decrypt
from CTF_Library.Cryptography.NumberTheory.CRT_coefficients import CRT_coefficients
from CTF_Library.Cryptography.Coppersmith.coppersmith import coppersmith_univariate
```

### Alternative: Root-Level Import

If compiled extensions are properly installed, you may be able to use:

```python
from CTF_Library import *
```

However, this may fail if there are issues with compiled C++ extensions. The `CTF_Library` package automatically imports all submodules and makes their functions available at the root level.

### Standard Library Imports

You'll still need to import standard libraries separately:

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
from Crypto.Util.Padding import pad, unpad
from sage.all import *
import hashlib
```

See `demo.py` in the repository root for a complete working example.

## Performance Considerations

- C++ extensions are compiled with `-O3 -march=native` for optimal performance
- Lattice reduction uses the `flatter` tool for faster computation
- Linear algebra over GF(2) uses optimized C++ implementation
- For large computations, consider using SageMath's parallel processing capabilities

## Best Practices

1. **Always validate inputs**: The library includes assertions, but you should validate external inputs
2. **Handle multiple solutions**: Many functions return lists of possible solutions
3. **Use appropriate bounds**: Coppersmith and lattice attacks require appropriate bounds
4. **Test with known values**: Verify your attack works on test cases before using on real challenges
5. **Monitor computation time**: Some attacks (especially lattice-based) can be computationally intensive

## Troubleshooting

### Import Errors

If you encounter import errors, ensure:

- SageMath is properly installed and in your PATH
- All C++ extensions compiled successfully
- Python version is 3.8 or higher

### Compilation Errors

If C++ extensions fail to compile:

- Ensure you have a C++ compiler with C++26 support
- Install pybind11: `pip install pybind11`
- Check that GMP libraries are installed (for ECDLP_bounded_impl)

### Runtime Errors

- Check that external tools (flatter, msolve, cuso) are in your PATH
- Verify SageMath version is 10.6 or higher
- Ensure all dependencies are correctly installed

## Contributing

Contributions are welcome. Please ensure:

- Code follows the existing style
- Functions include proper type hints and assertions
- Complex algorithms include comments explaining the approach
- Test cases are provided for new functionality

## License

[Specify license here]

## When to Use CTF_Lib

CTF_Lib is designed for:

- **Python-based CTF workflows**: Seamless integration with Python scripts and SageMath
- **Custom attack implementations**: When you need to modify or combine attacks
- **Lattice-based attacks**: Strong support for Coppersmith and lattice reduction
- **Elliptic curve attacks**: Comprehensive ECDLP and ECDSA attack suite
- **Research and learning**: Well-documented implementations for understanding attacks
- **Automated solving**: Easy integration into automated CTF solving pipelines

Consider using specialized tools (like RsaCtfTool) when:

- You need a quick, one-command solution for standard RSA attacks
- You're working with very large numbers requiring specialized factorization tools
- You need GUI-based tools for exploration and analysis
- You require tools with extensive attack databases and heuristics

## Related Tools and Libraries

While CTF_Lib provides a comprehensive set of cryptographic tools, there are several other excellent tools and libraries commonly used in CTF cryptography challenges that complement this library:

### RSA-Specific Tools

- **RsaCtfTool**: Comprehensive RSA attack tool with support for Wiener's attack, Håstad's broadcast attack, common factor attacks, and many factorization methods (Pollard's p-1, ECM, etc.)
  - GitHub: <https://github.com/RsaCtfTool/RsaCtfTool>

- **goRsaTool**: RSA tool written in Go, inspired by RsaCtfTool
  - GitHub: <https://github.com/sourcekris/goRsaTool>

### Factorization Tools

- **YAFU**: Automated integer factorization tool supporting multiple algorithms (SIQS, ECM, Pollard's rho, etc.)
  - Source: <https://github.com/bbuhrow/yafu>

- **CADO-NFS**: Implementation of the General Number Field Sieve (GNFS) for large integer factorization
  - Source: <https://gitlab.inria.fr/cado-nfs/cado-nfs>

- **Primefac**: Python library for integer factorization with multiple algorithms
  - PyPI: `pip install primefac`

### Lattice and Coppersmith Tools

- **fpylll**: Fast implementation of lattice reduction algorithms (LLL, BKZ)
  - GitHub: <https://github.com/fplll/fpylll>

- **ore_algebra**: SageMath package for operations on Ore polynomials, useful for certain Coppersmith attacks

### Hash and Encoding Tools

- **hashpump**: Tool for performing hash length extension attacks
  - GitHub: <https://github.com/bwall/HashPump>

- **hashcat**: Advanced password recovery tool supporting many hash algorithms
  - Website: <https://hashcat.net/hashcat/>

- **CyberChef**: Web-based tool for encoding, decoding, encryption, and data analysis
  - Website: <https://gchq.github.io/CyberChef/>

### Elliptic Curve Tools

- **ecdsa**: Python library for ECDSA operations
  - PyPI: `pip install ecdsa`

- **fastecdsa**: Fast elliptic curve cryptography library
  - GitHub: <https://github.com/AntonKueltz/fastecdsa>

### General CTF Crypto Tools

- **pycryptodome**: Comprehensive cryptographic library for Python
  - PyPI: `pip install pycryptodome`

- **cryptography**: Python library providing cryptographic recipes and primitives
  - PyPI: `pip install cryptography`

- **sage-crypto**: Additional cryptographic tools for SageMath

## Potential Future Enhancements

The following modules and features could be valuable additions to CTF_Lib for more comprehensive CTF cryptography support:

### RSA Attacks

- **Wiener's Attack**: For small private exponent d < n^0.25
- **Boneh-Durfee Attack**: Extended Wiener attack for d < n^0.292
- **Common Modulus Attack**: When same modulus is used with different exponents
- **Franklin-Reiter Related Message Attack**: For related messages encrypted with same modulus
- **Håstad's Broadcast Attack**: When same message is encrypted with small e to multiple recipients
- **Partial Key Exposure Attacks**: When parts of private key are leaked
- **Small Public Exponent Attacks**: Optimized attacks for e=3, e=5
- **ROCA Attack**: Attack on vulnerable RSA key generation (Infineon vulnerability)
- **Bleichenbacher Attack**: PKCS#1 v1.5 padding oracle attack
- **Manger Attack**: PKCS#1 v2.0 OAEP padding oracle attack

### Factorization Methods

- **Pollard's p-1 Method**: For factors where p-1 is smooth
- **Pollard's Rho Algorithm**: Probabilistic factorization method
- **Williams' p+1 Method**: For factors where p+1 is smooth
- **Elliptic Curve Method (ECM)**: For finding small factors
- **Self-Initializing Quadratic Sieve (SIQS)**: For medium-sized numbers
- **Continued Fraction Factorization**: For certain number patterns

### Hash Function Attacks

- **Length Extension Attacks**: For MD5, SHA1, SHA2 family
- **Hash Collision Attacks**: MD5, SHA1 collision detection
- **Hash-based MAC Attacks**: HMAC timing attacks, length extension

### Stream Cipher Attacks

- **RC4 Statistical Attacks**: Beyond FMS attack
- **LFSR Attacks**: Linear Feedback Shift Register cryptanalysis
- **ChaCha20 Analysis**: Stream cipher analysis tools

### Block Cipher Attacks

- **AES Key Recovery**: From side-channel information
- **DES Weak Keys**: Detection and exploitation
- **Meet-in-the-Middle Attacks**: For reduced-round ciphers
- **Differential/Linear Cryptanalysis**: Framework implementations

### Discrete Logarithm

- **Pohlig-Hellman Algorithm**: For composite order groups
- **Index Calculus Method**: For finite fields
- **Baby-Step Giant-Step**: Generic DLP solver
- **Pollard's Rho for DLP**: Probabilistic DLP solver

### Post-Quantum Cryptography

- **Lattice-Based Signature Attacks**: Analysis of post-quantum schemes
- **Code-Based Crypto**: McEliece, Niederreiter attacks
- **Isogeny-Based Crypto**: SIKE, CSIDH analysis

### Protocol Attacks

- **DSA/ECDSA Lattice Attacks**: For biased nonces (beyond simple reuse)
- **ElGamal Attacks**: Malleability, chosen ciphertext attacks
- **Diffie-Hellman Attacks**: Small subgroup attacks, invalid curve attacks

### Encoding and Steganography

- **Base Variants**: Base32, Base85, Base91, Base92
- **Morse Code**: Encoding/decoding utilities
- **ASCII Art Steganography**: Text-based steganography tools
- **LSB Steganography**: Image steganography basics

### Side-Channel Analysis

- **Timing Attack Framework**: Generic timing attack tools
- **Power Analysis**: Basic power analysis utilities

### Utilities

- **Integer Factorization API Integration**: Connect to online factorization services
- **Primality Testing**: Additional probabilistic tests (Lucas, Frobenius)
- **Quadratic Residuosity**: Legendre/Jacobi symbol calculations
- **Tonelli-Shanks Algorithm**: Square root modulo prime

## Integration with External Tools

CTF_Library can be used alongside the tools mentioned above. For example:

```python
from CTF_Library.Cryptography.Lattice.reduce_lattice import reduce_lattice
import subprocess

# Use RsaCtfTool for complex RSA attacks
result = subprocess.run(['RsaCtfTool.py', '-n', str(n), '-e', str(e)],
                       capture_output=True, text=True)

# Use YAFU for factorization
result = subprocess.run(['yafu', f'factor({n})'],
                       capture_output=True, text=True)

# Combine with CTF_Library's lattice reduction
from CTF_Library.Cryptography.Lattice.reduce_lattice import reduce_lattice
mat = construct_lattice_for_attack(...)
reduced = reduce_lattice(mat)  # Uses flatter via CTF_Library
```

## Acknowledgments

This library integrates and builds upon various open-source cryptographic tools and libraries, including SageMath, flint, flatter, msolve, cuso, and others mentioned in the dependencies. The design is inspired by the need for a unified, easy-to-use library for CTF cryptography challenges.
