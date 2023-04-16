from abc import abstractmethod, ABCMeta
from tqdm import tqdm
from core.utils import pformat, random_padding, unpad
import math

class AbstractEncryptor(metaclass=ABCMeta):
    '''
        可否认加密机的抽象接口
    '''
    def __init__(self, param:int):
        ''' 
            初始化一个加密器对象，其安全参数为param。
            param(int): 安全参数，通常为对称密码系统的位宽（本应用中为明文分组的长度，单位为字节。）
        '''   
        self.param = param
        self.keys:list[object] = list()
        self.alg_name = "Abstract"

    @abstractmethod
    def genkey(self) -> bytes:
        '''
            生成一个包含密钥信息的字节流，其中前4个字节为安全参数。
            return(bytes): 包含密钥及其他信息的字节流对象
        '''
        out = bytearray()
        out += self.param.to_bytes(4, 'big')
        print(pformat('Keygen', 'Producing Keypairs...'))
        return bytes(out)

    @abstractmethod
    def loadkey(self, keys:bytes):
        '''
            从密钥对象中加载密钥和其他所需信息。
            keys(bytes): genkey生成的密钥字节对象
        '''
        print(pformat('Keygen', 'Loaded Keypairs with ' + str(len(keys)) + ' bytes.'))
        self.param = int.from_bytes(keys[0:4], 'big')

    def flushkey(self) -> None:
        '''
            清除当前内存中的密钥。
        '''
        self.keys = []

    def encrypt(self, plains:tuple[bytes, bytes], padder=random_padding) -> bytes:
        '''
            （可否认地）加密指定的明文和虚假明文，使得密文能够解密为其中任意一个明文。
            plains(tuple[bytes, bytes]): 要加密的明文
            return(bytes): 加密的密文字节流
        '''
        maxl = math.ceil((max(len(plains[0]), len(plains[1])) + 4) / self.param)
        padded = (padder(plains[0], maxl, self.param), padder(plains[1], maxl, self.param))
        pre = self._prepare_enc(padded)
        with tqdm(total=maxl * self.param, desc=pformat('Encryption', 'Encrypting...'), unit='B', unit_scale=True, unit_divisor=1024) as pbar:
            for i in range(maxl):
                self._loop_enc(padded, pre, i)
                pbar.update(self.param)
        return bytes(pre['cipher'])

    def decrypt(self, cipher:bytes, honest:bool) -> bytes:
        '''
            使用指定的方法打开加密的字节流。
            cipher(bytes): 密文字节流
            honest(bool): 指定是否诚实地打开加密
            return(bytes): 使用指定密钥得到的明文
        '''
        pre = self._prepare_dec(cipher, honest)
        with tqdm(total=len(cipher), desc=pformat('Decryption', 'Decrypting...'), unit='B', unit_scale=True, unit_divisor=1024) as pbar:
            for i in range(len(cipher) // pre['tqdm_step']):
                self._loop_dec(cipher, pre, i)
                pbar.update(pre['tqdm_step'])
        return unpad(bytes(pre['plain']))

    #私有方法
    @abstractmethod
    def _prepare_enc(self, padded:tuple[bytes, bytes]) -> dict[str, object]:
        '''
        '''
        pass
    @abstractmethod
    def _loop_enc(self, padded, params:dict[str, object], i:int) -> None:
        '''
        '''
        pass
    @abstractmethod
    def _prepare_dec(self, cipher:bytes, honest:bool) -> dict[str, object]:
        '''
        '''
        pass
    @abstractmethod
    def _loop_dec(self, cipher, params:dict[str, object], i:int) -> None:
        '''
        '''
        pass