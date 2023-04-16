from core.encryptor import AbstractEncryptor
from core.utils import *
from Crypto.Util import number
from Crypto.PublicKey import ElGamal
from tqdm import tqdm
import math
import gmpy2
import random

class ElGamalEncryptor(AbstractEncryptor):
    def __init__(self, param:int):
        super().__init__(param)
        self.alg_name = "ElGamal"

    def genkey(self) -> bytes:
        out = super().genkey()
        key = ElGamal.generate(8 * self.param + 8, random.randbytes)
        out += int(key.p).to_bytes(self.param + 1, 'big')
        out += int(key.g).to_bytes(self.param + 1, 'big')
        out += int(key.y).to_bytes(self.param + 1, 'big')
        out += int(key.x).to_bytes(self.param + 1, 'big')
        return out

    def loadkey(self, keys:bytes):
        super().loadkey(keys)
        self.keys.append(int.from_bytes(keys[4:5 + self.param], 'big'))
        self.keys.append(int.from_bytes(keys[5 + self.param:6 + 2 * self.param], 'big'))
        self.keys.append(int.from_bytes(keys[6 + 2 * self.param:7 + 3 * self.param], 'big'))
        self.keys.append(int.from_bytes(keys[7 + 3 * self.param:8 + 4 * self.param], 'big'))

    def _prepare_enc(self, padded:tuple[bytes, bytes]) -> dict[str, object]:
        return {
            "cipher": bytearray()
        }
    def _loop_enc(self, padded:tuple[bytes, bytes], params:dict[str, object], i:int) -> None:
        mt = int.from_bytes(padded[0][i * self.param:(i + 1) * self.param], 'big')
        mf = int.from_bytes(padded[1][i * self.param:(i + 1) * self.param], 'big')
        a:int = gmpy2.powmod(self.keys[1], mf, self.keys[0]) * mt % self.keys[0]
        b:int = (gmpy2.powmod(self.keys[2], mf, self.keys[0]) * gmpy2.powmod(mt, self.keys[3], self.keys[0]) % self.keys[0]) * mf % self.keys[0]
        if(a == 0 or b == 0):
            print(pformat('Warn', 'Cipher is not inversible.'))
        params['cipher'] += int(a).to_bytes(self.param + 1, 'big')
        params['cipher'] += int(b).to_bytes(self.param + 1, 'big')
    def _prepare_dec(self, cipher:bytes, honest:bool) -> dict[str, object]:
        return {
            "tqdm_step": 2 * (self.param + 1),
            "plain": bytearray(),
            "honest": honest
        }
    def _loop_dec(self, cipher:bytes, params:dict[str, object], i:int) -> None:
        a = int.from_bytes(cipher[2 * i * (self.param + 1):(2 * i + 1) * (self.param + 1)], 'big')
        b = int.from_bytes(cipher[(2 * i + 1) * (self.param + 1):(2 * i + 2) * (self.param + 1)], 'big')
        mf = b * gmpy2.powmod(a, (-1) * self.keys[3], self.keys[0]) % self.keys[0]
        if(params['honest'] == False):
            params['plain'] += int(mf).to_bytes(self.param, 'big')
        else:
            m = a * gmpy2.powmod(self.keys[1], (-1) * mf, self.keys[0]) % self.keys[0]
            params['plain'] += int(m).to_bytes(self.param, 'big')