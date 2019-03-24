from nem_ed25519 import get_ek, dummy_ek, decode_ek, is_ek, convert_ek
from nem_ed25519 import secret_key, public_key


def main():
    sk = secret_key()
    pk = public_key(sk)
    ek = get_ek(pk, prefix=b'\x00')
    assert pk == decode_ek(ek)
    assert is_ek(ek)
    assert is_ek(ek, prefix=b'\x00')
    other_ek = convert_ek(ek, prefix=b'\x01')
    assert is_ek(other_ek)
    assert not is_ek(other_ek, prefix=b'\x00')
    assert is_ek(other_ek, prefix=b'\x01')
    d_ek = dummy_ek("NAMUYAN", b'\x02')
    print(d_ek, is_ek(d_ek))
    for index in range(0, 255):
        prefix = index.to_bytes(1, 'big')
        print("{:10} {}".format(str(prefix), get_ek(pk, prefix)))


if __name__ == '__main__':
    main()
