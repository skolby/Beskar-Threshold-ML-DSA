# SageMath script to generate F2_128 test vectors for this package.
# Field: GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)
# Representation: integer bits map to polynomial coefficients,
# with bit i corresponding to x^i. The Go type stores this as
# lo = bits [0..63], hi = bits [64..127].

R.<x> = GF(2)[]
MOD = x^128 + x^7 + x^2 + x + 1
F.<a> = GF(2^128, modulus=MOD)
MASK64 = (Integer(1) << 64) - 1


def pack(hi, lo):
    return (Integer(hi) << 64) + Integer(lo)


def unpack(n):
    return ((n >> 64) & MASK64, n & MASK64)


def elem_to_int(e):
    # Sage 10.9 finite field elements do not coerce directly to int,
    # so rebuild the integer from polynomial coefficients.
    n = Integer(0)
    for i, c in enumerate(e.list()):
        if int(c) & 1:
            n += Integer(1) << i
    return n


def inv_hi_lo(hi, lo):
    n = pack(hi, lo)
    inv = ~F.from_integer(n)
    return unpack(elem_to_int(inv))


def mul_hi_lo(x_hi, x_lo, y_hi, y_lo):
    xn = pack(x_hi, x_lo)
    yn = pack(y_hi, y_lo)
    prod = F.from_integer(xn) * F.from_integer(yn)
    return unpack(elem_to_int(prod))


inv_cases = [
    (0x0000000000000000, 0x0000000000000002),
    (0x8000000000000000, 0x0000000000000001),
    (0xabcdef0123456789, 0x13579bdf2468ace0),
    (0xffffffffffffffff, 0xffffffffffffffff),
    (0x0123456789abcdef, 0x0000000000000001),
]

print("# Inversion vectors")
for hi, lo in inv_cases:
    ihi, ilo = inv_hi_lo(hi, lo)
    print(
        f"x={{hi:0x{hi:016x}, lo:0x{lo:016x}}} "
        f"inv={{hi:0x{ihi:016x}, lo:0x{ilo:016x}}}"
    )


mul_cases = [
    (0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444),
    (0xdeadbeefdeadbeef, 0x0123456789abcdef, 0x0f0e0d0c0b0a0908, 0x0706050403020100),
]

print("\n# Multiplication vectors")
for x_hi, x_lo, y_hi, y_lo in mul_cases:
    phi, plo = mul_hi_lo(x_hi, x_lo, y_hi, y_lo)
    print(
        f"x={{hi:0x{x_hi:016x}, lo:0x{x_lo:016x}}} "
        f"y={{hi:0x{y_hi:016x}, lo:0x{y_lo:016x}}} "
        f"prod={{hi:0x{phi:016x}, lo:0x{plo:016x}}}"
    )
