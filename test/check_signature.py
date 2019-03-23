import os
from time import time
from nem_ed25519 import sign, verify

sk = '78f8932df54d22319a16dc4940c269205ae0946f98d38ef30aea488a47426153'
pk = '77041bfb4b6afebc31aaab7b02d68e577fe069524b3c661c804b42ef381f717b'
ck = 'NBOGOGSENUPBFMAPTGHVI4UIAQPVSNKJLWUVHBED'

COUNT = 300


def main():
    start = time()
    sign_list = list()

    for i in range(COUNT):
        msg = os.urandom(i+1)
        signature = sign(msg, sk, pk)
        sign_list.append((msg, signature))

    for msg, signature in sign_list:
        verify(msg, signature, pk)
    print(round((time()-start)*1000/COUNT, 3), 'mS/sign&verify')

# before 3.85 mS/sign&verify


if __name__ == '__main__':
    main()
