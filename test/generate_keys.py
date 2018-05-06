from nem_ed25519.key import secret_key, public_key, get_address, dummy_address, is_address
import time
import cProfile


start = time.time()
result = list()
COUNT = 10
pr = cProfile.Profile()
pr.enable()
for i in range(COUNT):
    sk = secret_key()
    pk = public_key(sk)
    ck = get_address(pk)
    if not is_address(ck):
        raise Exception('not correct key')
    result.append((sk, pk, ck))
pr.disable()
print((time.time()-start) * 1000 // COUNT, "mS/create_pair")

print("\ntry check")
sk = '78f8932df54d22319a16dc4940c269205ae0946f98d38ef30aea488a47426153'
pk = '77041bfb4b6afebc31aaab7b02d68e577fe069524b3c661c804b42ef381f717b'
ck = 'NBOGOGSENUPBFMAPTGHVI4UIAQPVSNKJLWUVHBED'
assert pk == public_key(sk), 'Not correct sk'
assert ck == get_address(pk), 'Not correct pk'
print("all ok.")

address = dummy_address('NAMUYAN')
print("dummy address", address, is_address(address))
pr.print_stats()
