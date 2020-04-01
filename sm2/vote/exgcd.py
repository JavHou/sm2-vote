def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)


def exgcd(a, b):
    x1, x0 = 1, 0
    y1, y0 = 0, 1
    q = a // b
    r1, r0 = b, a % b
    while r0:
        x1, x0 = x0, x1 - q * x0
        y1, y0 = y0, y1 - q * y0
        q = r1 // r0
        r1, r0 = r0, r1 % r0
    return r1, x0, y0


def _grgcd(a, b, x, y):
    if not b:
        x[0], y[0] = 1, 0
        return a
    d = _grgcd(b, a % b, y, x)
    y[0] -= a // b * x[0]
    return d


def grgcd(a, b):
    x, y = [0], [0]
    d = _grgcd(a, b, x, y)
    return d, x[0], y[0]


def inverse(a, m):
    d, x, y = exgcd(a, m)
    if d == 1:
        return x % m
    else:
        return -1


if __name__ == '__main__':
    import timeit

    print(exgcd(58, 689))
    print(grgcd(58, 689))
    print(inverse(7, 26))
