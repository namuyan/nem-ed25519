from collections import namedtuple

Point = namedtuple('Point', ['x', 'y'])

PRIME = PRIME = 2 ** 255 - 19

def inverse(x):
    return pow(x, PRIME - 2, PRIME)


D = -121665 * inverse(121666) % PRIME


def outer(P, n):
    def _inner(px, py, qx, qy):
        x = (px * qy + qx * py) * inverse(1 + D * px * qx * py * qy)
        y = (py * qy + px * qx) * inverse(1 - D * px * qx * py * qy)
        return x % PRIME, y % PRIME

    def _outer(px, py, _n):
        if _n == 0:
            return 0, 1
        qx, qy = _outer(px, py, _n // 2)
        qx, qy = _inner(qx, qy, qx, qy)
        if _n & 1:
            qx, qy = _inner(qx, qy, px, py)
        return qx, qy

    _qx, _qy = _outer(P.x, P.y, n)
    return Point(_qx, _qy)
