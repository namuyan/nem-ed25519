import os
import time

from nem_ed25519.encrypt import encrypt, decrypt

sk0 = '78f8932df54d22319a16dc4940c269205ae0946f98d38ef30aea488a47426153'
pk0 = '77041bfb4b6afebc31aaab7b02d68e577fe069524b3c661c804b42ef381f717b'
sk1 = '5c89d05c0b3e873a40893940b5c3a8a7462db9a589e8f72024584d43dd80538c'
pk1 = '20393a01db281a73af258ef2f515fbcc3d6fd674a97fcce99fc4f9cd812f4a34'

COUNT = 100
start = time.time()
for i in range(COUNT):
    msg = os.urandom(i+1)
    enc = encrypt(sk0, pk1, msg)
    dec = decrypt(sk1, pk0, enc)
    assert msg == dec, 'Not correct!'
print((time.time()-start) * 1000 // COUNT, 'mS/encrypt&decrypt')
