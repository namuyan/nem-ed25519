import os
from time import time
from nem_ed25519.signature import sign, verify
import cProfile

sk = '78f8932df54d22319a16dc4940c269205ae0946f98d38ef30aea488a47426153'
pk = '77041bfb4b6afebc31aaab7b02d68e577fe069524b3c661c804b42ef381f717b'
ck = 'NBOGOGSENUPBFMAPTGHVI4UIAQPVSNKJLWUVHBED'

COUNT = 300
start = time()
pr = cProfile.Profile()

sign_list = list()
pr.enable()
for i in range(COUNT):
    msg = os.urandom(i+1)
    signature = sign(msg, sk, pk)
    sign_list.append((msg, signature))
# pr.disable()

for msg, signature in sign_list:
    verify(msg, signature, pk)
pr.disable()
print(round((time()-start)*1000/COUNT, 3), 'mS/sign&verify')
pr.print_stats()

# before 11.52 mS/sign&verify
