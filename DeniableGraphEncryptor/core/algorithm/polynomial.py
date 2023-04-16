from Crypto.Util import number
from random import Random
from tqdm import tqdm
import gmpy2
import secrets
import math
from core.utils import *
from core.encryptor import AbstractEncryptor
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import current_process, RLock, freeze_support

class PolynomialEncryptor(AbstractEncryptor):
    def __init__(self, param):
        super().__init__(param)
        self.alg_name = "Polynomial"

    def loadkey(self, keys:bytes):
        super().loadkey(keys)
        self.prime = int.from_bytes(keys[4:5 + self.param], 'big')
        self.keys = []
        for i in range(2):
            self.keys.append(int.from_bytes(keys[5 + (i + 1) * self.param: 5 + (i + 2) * self.param], 'big'))

    def genkey(self) -> bytes:
        out = bytearray(super().genkey())
        out += number.getPrime(self.param * 8 + 8).to_bytes(self.param + 1, 'big')
        for i in range(2):
            out += secrets.randbits(self.param * 8).to_bytes(self.param, 'big')
        return bytes(out)

    def _prepare_enc(self, padded:tuple[bytes, bytes]) -> dict[str, object]:
        if(len(self.keys) < 2):
            raise ValueError
        
        maxl = len(padded[0]) // self.param

        freeze_support()
        tqdm.set_lock(RLock())
        pool = ProcessPoolExecutor(max_workers=2, initializer=tqdm.set_lock, initargs=(tqdm.get_lock(),))
        p1 = pool.submit(rand_handler, self.param, Random(self.keys[0]), maxl)
        p2 = pool.submit(rand_handler, self.param, Random(self.keys[1]), maxl)

        pool.shutdown(wait=True)

        return {
            "cipher": bytearray(), 
            "randt": p1.result(), "randf": p2.result()
            }
    def _loop_enc(self,padded:tuple[bytes, bytes], params:dict[str, object], i:int) -> None:
        '''
           Encrypt: 
           Assume L[i](x) = u[i] * x + v[i], L[i](a1[i]) = m1[i] + b1[i], L[i](a2[i]) = m2[i] + b2[i]
            => u[i] * a1[i] + v[i] = m1[i] + b1[i]
            u[i] * a2[i] + v[i] = m2[i] + b2[i]
            => u[i] * (a1[i] - a2[i]) = (m1[i] - m2[i] + b1[i] - b2[i])
            if a1[i] != a2[i] 
            => u[i] = (m1[i] - m2[i] + b1[i] - b2[i]) * (a1[i] - a2[i])^(-1)
            if a1[i] == a2[i], algorithm will corrupt.(since the pseudo generator has a period of 2^19937 - 1, this is a small chance event.)
            => v[i] * (a2[i] - a1[i]) = m1[i] * a2[i] - m2 * a1[i] + b1[i] * a2[i] - b2[i] * a1[i]
            => v[i] = (m2[i] * a1[i] - m1 * a2[i] + b2[i] * a1[i] - b1[i] * a2[i]) * (a1[i] - a2[i])^(-1)

            About 100k it/s(256bit key), ~2MB/s
        '''
        m1 = int.from_bytes(padded[0][i * self.param:(i + 1) * self.param], 'big')
        m2 = int.from_bytes(padded[1][i * self.param:(i + 1) * self.param], 'big')
        a1, b1 = params['randt'][i]
        a2, b2 = params['randf'][i]
        r = int(gmpy2.invert(a1 - a2, self.prime))
        u = ((m1 - m2 + b1 - b2) * r) % self.prime
        v = ((m2 * a1 - m1 * a2 + b2 * a1 - b1 * a2) * r) % self.prime

        params['cipher'] += int(u).to_bytes(self.param + 1, 'big')
        params['cipher'] += int(v).to_bytes(self.param + 1, 'big')
    def _prepare_dec(self, cipher:bytes, honest:bool) -> dict[str, object]:
        key = self.keys[1]
        if(honest):
            key = self.keys[0]
        randgen = Random(key)
        return {
            "tqdm_step": 2 * (self.param + 1),
            "plain": bytearray(),
            "randgen": randgen,
        }
    def _loop_dec(self, cipher:bytes, params:dict[str, object], i:int) -> None:
        a, b = nextrand(self.param, params['randgen'])
        u = int.from_bytes(cipher[2 * i * (self.param + 1):(2 * i + 1) * (self.param + 1)], 'big')
        v = int.from_bytes(cipher[(2 * i + 1) * (self.param + 1):(2 * i + 2) * (self.param + 1)], 'big')
        m = (u * a + v - b) % self.prime
        params['plain'] += int(m).to_bytes(self.param, 'big')

def nextrand(param, randgen:Random) -> tuple[int, int]:
    l = param * 8
    nxt = randgen.getrandbits(3 * l).to_bytes(3 * param, 'big')

    b = int.from_bytes(nxt[2 * param: 3 * param], 'big')
    a = int.from_bytes(nxt[param: 2 * param], 'big')
    k = int.from_bytes(nxt[0:param], 'big')

    randgen.seed(k)
    return (a, b)

def rand_handler(param, randgen:Random, l:int):
    keys = list()
    pid = int(current_process().name[-1]) - 1
    for i in tqdm(range(l), desc=pformat('Keygen', 'Streaming keys...'), unit='Blocks', unit_scale=True, ascii=False):
        keys.append(nextrand(param, randgen))
    return keys
