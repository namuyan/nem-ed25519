#!/user/env python3
# -*- coding: utf-8 -*-

from collections import namedtuple
from operator import getitem
from sha3 import keccak_256, keccak_512

Point = namedtuple('Point', ['x', 'y'])
KEY_MASK = int.from_bytes(b'\x3F' + b'\xFF' * 30 + b'\xF8', 'big', signed=False)
B = 256
PRIME = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
IDENT = (0, 1, 1, 0)


def to_hash(m):
    return keccak_512(m).digest()


def to_hash_sha3_256(m):
    return keccak_256(m).digest()


def to_bytes(i):
        return i.to_bytes(B // 8, 'little', signed=False)


def from_bytes(h):
    """ pick 32 bytes, return a 256 bit int """
    return int.from_bytes(h[0:B // 8], 'little', signed=False)


def int2byte(i):
    return i.to_bytes(1, "big")


def as_key(h):
    return 2 ** (B - 2) + (from_bytes(h) & KEY_MASK)


def point_to_bytes(P):
    return (P.y + ((P.x & 1) << 255)).to_bytes(B // 8, 'little')


def inverse(x):
    return pow(x, PRIME - 2, PRIME)


D = -121665 * inverse(121666) % PRIME


def inner(P, Q):
    """ inner product on the curve, between two points """
    x = (P.x * Q.y + Q.x * P.y) * inverse(1 + D * P.x * Q.x * P.y * Q.y)
    y = (P.y * Q.y + P.x * Q.x) * inverse(1 - D * P.x * Q.x * P.y * Q.y)
    return Point(x % PRIME, y % PRIME)


def outer(P, n):
    """ outer product on the curve, between a point and a scalar """
    if n == 0:
        return Point(0, 1)
    Q = outer(P=P, n=n // 2)
    Q = inner(P=Q, Q=Q)
    if n & 1:
        Q = inner(P=Q, Q=P)
    return Q


def bit(h, i):
    return (getitem(h, i // 8) >> (i % 8)) & 1


def Hint_hash(m):
    h = keccak_512(m).digest()
    return sum(2 ** i * bit(h, i) for i in range(2 * B))


def edwards_add(P, Q):
    # This is formula sequence 'addition-add-2008-hwcd-3' from
    # http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    (x1, y1, z1, t1) = P
    (x2, y2, z2, t2) = Q

    a = (y1 - x1) * (y2 - x2) % PRIME
    b = (y1 + x1) * (y2 + x2) % PRIME
    c = t1 * 2 * D * t2 % PRIME
    dd = z1 * 2 * z2 % PRIME
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g
    return x3 % PRIME, y3 % PRIME, z3 % PRIME, t3 % PRIME


def edwards_double(P):
    # This is formula sequence 'dbl-2008-hwcd' from
    # http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    (x1, y1, z1, t1) = P

    a = x1 * x1 % PRIME
    b = y1 * y1 % PRIME
    c = 2 * z1 * z1 % PRIME
    # dd = -a
    e = ((x1 + y1) * (x1 + y1) - a - b) % PRIME
    g = -a + b  # dd + b
    f = g - c
    h = -a - b  # dd - b
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g
    return x3 % PRIME, y3 % PRIME, z3 % PRIME, t3 % PRIME


def pow2(x, p):
    """== pow(x, 2**p, q)"""
    while p > 0:
        x = x * x % PRIME
        p -= 1
    return x


def inv(z):
    """$= z^{-1} \mod q$, for z != 0"""
    # Adapted from curve25519_athlon.c in djb's Curve25519.
    z2 = z * z % PRIME  # 2
    z9 = pow2(z2, 2) * z % PRIME  # 9
    z11 = z9 * z2 % PRIME  # 11
    z2_5_0 = (z11 * z11) % PRIME * z9 % PRIME  # 31 == 2^5 - 2^0
    z2_10_0 = pow2(z2_5_0, 5) * z2_5_0 % PRIME  # 2^10 - 2^0
    z2_20_0 = pow2(z2_10_0, 10) * z2_10_0 % PRIME  # ...
    z2_40_0 = pow2(z2_20_0, 20) * z2_20_0 % PRIME
    z2_50_0 = pow2(z2_40_0, 10) * z2_10_0 % PRIME
    z2_100_0 = pow2(z2_50_0, 50) * z2_50_0 % PRIME
    z2_200_0 = pow2(z2_100_0, 100) * z2_100_0 % PRIME
    z2_250_0 = pow2(z2_200_0, 50) * z2_50_0 % PRIME  # 2^250 - 2^0
    return pow2(z2_250_0, 5) * z11 % PRIME  # 2^255 - 2^5 + 11 = q - 2


def xrecover(y):
    xx = (y * y - 1) * inv(D * y * y + 1)
    x = pow(xx, (PRIME + 3) // 8, PRIME)

    if (x * x - xx) % PRIME != 0:
        I = pow(2, (PRIME - 1) // 4, PRIME)
        x = (x * I) % PRIME

    if x % 2 != 0:
        x = PRIME - x
    return x


def make_Bpow():
    By = 4 * inv(5)
    Bx = xrecover(By)
    P = (Bx % PRIME, By % PRIME, 1, (Bx * By) % PRIME)
    Bpow = list()
    for i in range(253):
        Bpow.append(P)
        P = edwards_double(P)
    return Bpow


Bpow = make_Bpow()


def scalarmult_B(e):
    """
    Implements scalarmult(B, e) more efficiently.
    """
    # scalarmult(B, l) is the identity
    e %= L
    P = IDENT
    for i in range(253):
        if e & 1:
            P = edwards_add(P, Bpow[i])
        e //= 2
    assert e == 0, e
    return P


def scalarmult(P, e):
    if e == 0:
        return IDENT
    Q = scalarmult(P, e // 2)
    Q = edwards_double(Q)
    if e & 1:
        Q = edwards_add(Q, P)
    return Q


def isoncurve(P):
    (x, y, z, t) = P
    return (z % PRIME != 0 and
            x * y % PRIME == z * t % PRIME and
            (y * y - x * x - z * z - D * t * t) % PRIME == 0)


def encodepoint(P):
    (x, y, z, t) = P
    zi = inv(z)
    x = (x * zi) % PRIME
    y = (y * zi) % PRIME
    bits = [(y >> i) & 1 for i in range(B - 1)] + [x & 1]
    return b''.join([
            int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
            for i in range(B // 8)
        ])


def encodeint(y):
    bits = [(y >> i) & 1 for i in range(B)]
    return b''.join([
            int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
            for i in range(B // 8)
        ])


def decodepoint(s):
    y = sum(2 ** i * bit(s, i) for i in range(0, B - 1))
    x = xrecover(y)
    if x & 1 != bit(s, B - 1):
        x = PRIME - x
    P = (x, y, 1, (x * y) % PRIME)
    if not isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def decodeint(s):
    return sum(2 ** i * bit(s, i) for i in range(0, B))


def pad(s):
    pad = 32 - len(s) % 32
    add = 32 - len(s) % 32
    return s + add * pad.to_bytes(1, 'big')


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def recover(y):
    """ given a value y, recover the preimage x """
    p = (y * y - 1) * inverse(D * y * y + 1)
    x = pow(p, (PRIME + 3) // 8, PRIME)
    if (x * x - p) % PRIME != 0:
        i = pow(2, (PRIME - 1) // 4, PRIME)
        x = (x * i) % PRIME
    if x % 2 != 0:
        x = PRIME - x
    return x


def point(y):
    """ given a value y, recover x and return the corresponding P(x, y) """
    return Point(recover(y) % PRIME, y % PRIME)


B_POINT = point(4 * inverse(5))
