from core.encryptor import AbstractEncryptor
from core.utils import *
from tqdm import tqdm
from random import Random
import secrets
import math

class SerialEncryptor(AbstractEncryptor):
    def __init__(self, param:int):
        super().__init__(param)
        self.alg_name = "Serial"

    def genkey(self) -> bytes:
        out = super().genkey()
        out += secrets.randbits(8 * self.param).to_bytes(self.param, 'big')
        out += secrets.randbits(8 * self.param).to_bytes(self.param, 'big')
        return out

    def loadkey(self, keys:bytes):
        super().loadkey(keys)
        self.keys.append(int.from_bytes(keys[4:4 + self.param], 'big'))
        self.keys.append(int.from_bytes(keys[4 + self.param:4 + 2 * self.param], 'big'))

    def _prepare_enc(self, padded:tuple[bytes, bytes]) -> dict[str, object]:
        maxl = len(padded[0]) // self.param
        return {
            "cipher": bytearray(),
            "ks1": keystream(self.keys[0], Random(), maxl, self.param),
            "ks2": keystream(self.keys[1], Random(), maxl, self.param)
        }
    def _loop_enc(self, padded:tuple[bytes, bytes], params:dict[str, object], i:int) -> None:
        k1 = params['ks1'][i * self.param:(i + 1) * self.param]
        k2 = params['ks2'][i * self.param:(i + 1) * self.param]
        params['cipher'] += bxor(padded[0][i * self.param:(i + 1) * self.param], k1)
        params['cipher'] += bxor(padded[1][i * self.param:(i + 1) * self.param], k2)
    def _prepare_dec(self, cipher:bytes, honest:bool) -> dict[str, object]:
        rand = Random()
        l = len(cipher) // self.param
        ks = bytes()
        if(honest):
            ks = keystream(self.keys[0], rand, l // 2, self.param)
        else:
            ks = keystream(self.keys[1], rand, l // 2, self.param)
        return {
            "tqdm_step": 2 * self.param,
            "ks": ks,
            "plain": bytearray(),
            "honest": honest
        }
    def _loop_dec(self, cipher:bytes, params:dict[str, object], i:int) -> None:
        k = params['ks'][i * self.param:(i + 1) * self.param]
        c = bytes()
        if(params['honest']):
            c = cipher[2 * i * self.param:(2 * i + 1) * self.param]
        else:
            c = cipher[(2 * i + 1) * self.param:(2 * i + 2) * self.param]
        params['plain'] += bxor(c, k)

def bxor(b1:bytes, b2:bytes) -> bytearray:
    r = bytearray()
    for b1, b2 in zip(b1, b2):
        r.append(b1 ^ b2)
    return r

def keystream(key:int, rand:Random, l:int, b:int) -> bytes:
    rand.seed(key)
    ks = bytearray()
    for i in tqdm(range(l), desc=pformat('Keygen', 'Streaming key...'), unit='Blocks', unit_scale=True):
        ks += rand.randbytes(b)
    return bytes(ks)
