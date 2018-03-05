#!/user/env python3
# -*- coding: utf-8 -*-

from nem_ed25519.key import secret_key, public_key, get_address
import time

b32alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
request = 'NAMU'
main_net = True
prefix = None

for i in list(request):
    if i not in b32alphabet:
        raise ValueError('\"%s\" is not include base32 strings.' % i)

count = 0
start = time.time()
print("Prefix={}, mainnet={}, Find \"{}\"".format(prefix, main_net, request))
while True:
    count += 1
    sk = secret_key()
    pk = public_key(sk)
    ck = get_address(pk, main_net, prefix)
    if request in ck:
        print("Secret", sk)
        print("Public", pk)
        print("Compressed", ck)
        print("finished")
        exit(0)
    elif count % 100 == 0:
        print("{}processed, {}mS/cycle".format(count, (time.time()-start)*1000//count))
    else:
        continue
