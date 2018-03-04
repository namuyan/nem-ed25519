#!/user/env python3
# -*- coding: utf-8 -*-

from binascii import unhexlify
from .utils import *


def sign(msg, sk, pk):
    assert isinstance(msg, bytes), 'Msg is bytes'
    assert isinstance(sk, str), 'SK is hex str'
    assert isinstance(pk, str), 'PK is hex str'
    sk = unhexlify(sk.encode())[::-1]
    pk = unhexlify(pk.encode())

    h = to_hash(sk)
    a = 2 ** (B - 2) + sum(2 ** i * bit(h, i) for i in range(3, B - 2))

    m_raw = bytes([getitem(h, j) for j in range(B // 8, B // 4)]) + msg
    r = Hint_hash(m_raw)

    R = scalarmult_B(r)
    S = (r + Hint_hash(encodepoint(R) + pk + msg) * a) % L
    return encodepoint(R) + encodeint(S)


def verify(msg, sign, pk):
    assert isinstance(msg, bytes), 'Msg is bytes'
    assert isinstance(sign, bytes), 'Sign is bytes'
    assert isinstance(pk, str), 'PK is hex str'
    pk = unhexlify(pk.encode())
    if len(sign) != B // 4:
        raise ValueError("signature length is wrong")

    if len(pk) != B // 8:
        raise ValueError("public-key length is wrong")

    try:
        R = decodepoint(sign[:B // 8])
        A = decodepoint(pk)
        S = decodeint(sign[B // 8:B // 4])
        h = Hint_hash(encodepoint(R) + pk + msg)

        (x1, y1, z1, t1) = P = scalarmult_B(S)
        (x2, y2, z2, t2) = Q = edwards_add(R, scalarmult(A, h))

        f_P_on = not isoncurve(P)
        f_Q_on = not isoncurve(Q)
        f_X_on = (x1 * z2 - x2 * z1) % PRIME != 0
        f_Y_on = (y1 * z2 - y2 * z1) % PRIME != 0
    except Exception as e:
        raise ValueError(e)

    if f_P_on or f_Q_on or f_X_on or f_Y_on:
        raise ValueError('Not correct signature.')
