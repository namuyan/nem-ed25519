import os
import time

from nem_ed25519.signature import sign, verify

sk = '78f8932df54d22319a16dc4940c269205ae0946f98d38ef30aea488a47426153'
pk = '77041bfb4b6afebc31aaab7b02d68e577fe069524b3c661c804b42ef381f717b'
ck = 'NBOGOGSENUPBFMAPTGHVI4UIAQPVSNKJLWUVHBED'

COUNT = 100
start = time.time()
for i in range(COUNT):
    msg = os.urandom(i+1)
    signature = sign(msg, sk, pk)
    verify(msg, signature, pk)
print((time.time()-start) * 1000 // COUNT, 'mS/sign&verify')
