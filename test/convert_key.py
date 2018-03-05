#!/user/env python3
# -*- coding: utf-8 -*-

from nem_ed25519.key import secret_key, public_key, get_address, convert_address

result = list()
for i in range(255):
    sk = secret_key()
    pk = public_key(sk)
    ck = get_address(pk, prefix=i.to_bytes(1, 'big'))
    result.append("{:10}{}".format(str(i.to_bytes(1, 'big')), ck))
print("\n".join(result))
