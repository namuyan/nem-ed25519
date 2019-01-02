#!/user/env python3
# -*- coding: utf-8 -*-

from collections import namedtuple
from operator import getitem
from sha3 import keccak_256, keccak_512
from gmpy_cffi import mpz

Point = namedtuple('Point', ['x', 'y'])
KEY_MASK = int.from_bytes(b'\x3F' + b'\xFF' * 30 + b'\xF8', 'big', signed=False)
B = mpz(256)
PRIME = mpz(2 ** 255 - 19)
L = mpz(2 ** 252 + 27742317777372353535851937790883648493)
IDENT = (mpz(0), mpz(1), mpz(1), mpz(0))


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
    return int(i).to_bytes(1, "big")


def as_key(h):
    return 2 ** (B - 2) + (from_bytes(h) & KEY_MASK)


def point_to_bytes(P):
    return (P.y + ((P.x & 1) << 255)).to_bytes(B // 8, 'little')


num_prime = mpz(PRIME)
num_prime_minus_2 = mpz(PRIME - 2)


def inverse(x):
    return pow(x, num_prime_minus_2, num_prime)


D = -121665 * inverse(mpz(121666)) % PRIME
num_minus_1 = mpz(-1)
num_0 = mpz(0)
num_1 = mpz(1)
num_d = mpz(D)


def _inner(px, py, qx, qy):
    base_x = num_1 + num_d * px * qx * py * qy
    base_y = num_1 - num_d * px * qx * py * qy
    x = (px * qy + qx * py) * pow(base_x, num_prime_minus_2, num_prime)
    y = (py * qy + px * qx) * pow(base_y, num_prime_minus_2, num_prime)
    return x % PRIME, y % PRIME


def _outer(px, py, n):
    if n == num_0:
        return num_0, num_1
    qx, qy = _outer(px, py, n // 2)
    qx, qy = _inner(qx, qy, qx, qy)
    if n & 1:
        qx, qy = _inner(qx, qy, px, py)
    return qx, qy


def outer(P, n):
    qx, qy = _outer(mpz(P.x), mpz(P.y), mpz(n))
    return Point(int(qx), int(qy))


def bit(h, i):
    return (getitem(h, i // 8) >> (i % 8)) & 1


def Hint_hash(m):
    h = keccak_512(m).digest()
    # return sum(2 ** i * bit(h, i) for i in range(2 * B))
    # sum(2 ** i * bit(h, i) for i in range(0, 512)) == int.from_bytes(h, 'little')
    return int.from_bytes(h, 'little')


def edwards_add(P, Q):
    # This is formula sequence 'addition-add-2008-hwcd-3' from
    # http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q

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
    x1, y1, z1, t1 = P

    a = x1 ** 2 % PRIME
    b = y1 ** 2 % PRIME
    c = 2 * (z1 ** 2) % PRIME
    # dd = -a
    e = ((x1 + y1) ** 2 - a - b) % PRIME
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
    return pow(x, 2**p, PRIME)
    # while p > 0:
    #    x = x * x % PRIME
    #    p -= 1
    # return x


def inv(z):
    """$= z^{-1} \mod q$, for z != 0"""
    # Adapted from curve25519_athlon.c in djb's Curve25519.
    z = mpz(z)
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
        I = pow(mpz(2), (PRIME - 1) // 4, PRIME)
        x = (x * I) % PRIME

    if x % 2 != 0:
        x = PRIME - x
    return x


def make_Bpow():
    By = 4 * inv(5)
    Bx = xrecover(By)
    P = (Bx % PRIME, By % PRIME, num_1, (Bx * By) % PRIME)
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
    if x & 1 == 1:
        y += 2**255
    return int(y).to_bytes(B//8, 'little')
    # bits = [(y >> i) & 1 for i in range(B - 1)] + [x & 1]
    # return b''.join([
    #        int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
    #        for i in range(B // 8)
    #    ])


def encodeint(y):
    return int(y).to_bytes(B//8, 'little')
    # bits = [(y >> i) & 1 for i in range(B)]
    # return b''.join([
    #        int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
    #        for i in range(B // 8)
    #    ])


def decodepoint(s):
    # bytes to Point
    # y = sum(2 ** i * bit(s, i) for i in range(0, B - 1))
    y = decodeint(s) - 2 ** 255 * bit(s, 255)
    y = mpz(y)
    x = xrecover(y)
    if x & 1 != bit(s, B - 1):
        x = PRIME - x
    P = (x, y, mpz(1), (x * y) % PRIME)
    if not isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def decodeint(s):
    # return sum(2 ** i * bit(s, i) for i in range(0, B))
    return int.from_bytes(s[:B], 'little')


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
        i = pow(mpz(2), (PRIME - 1) // 4, PRIME)
        x = (x * i) % PRIME
    if x % 2 != 0:
        x = PRIME - x
    return x


def point(y):
    """ given a value y, recover x and return the corresponding P(x, y) """
    return Point(recover(y) % PRIME, y % PRIME)


B_POINT = point(4 * inverse(mpz(5)))
