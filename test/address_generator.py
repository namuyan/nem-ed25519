#!/user/env python3
# -*- coding: utf-8 -*-

from nem_ed25519 import secret_key, public_key, get_address
from multiprocessing import Process, Queue
import time

b32alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'


def main(cores=3):
    request = 'NAMUYAN'
    main_net = True
    prefix = None

    for i in list(request):
        if i not in b32alphabet:
            raise ValueError('\"%s\" is not include base32 strings.' % i)

    process = list()
    que = Queue()
    count = 0
    start = time.time()
    for i in range(cores):
        p = Process(target=_process, args=(que, i, request, main_net, prefix))
        process.append(p)
        p.start()
    while True:
        data = que.get()
        if data[0]:
            print("Secret", data[1])
            print("Public", data[2])
            print("Compressed", data[3])
            print("finished")
            exit(0)
        elif data[1] == 0:
            count += data[2]
            print("{}, {}mS/cycle".format(count, round((time.time()-start)*1000/count, 3)))
        else:
            count += data[2]


def _process(que, number, request, main_net, prefix):
    count = 0
    while True:
        count += 1
        sk = secret_key()
        pk = public_key(sk)
        ck = get_address(pk, main_net, prefix)
        if request in ck:
            que.put((True, sk, pk, ck))
            exit(1)
        elif count % 100 == 0:
            que.put((False, number, count))
            count = 0


if __name__ == '__main__':
    main()
