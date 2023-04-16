from core.encryptor import AbstractEncryptor

class PatternEncryptor(AbstractEncryptor):
    '''
    Pattern Encryptor for interface implementation
    '''
    def __init__(self, param:int):
        super().__init__(param)
        self.alg_name = "Pattern"

    def genkey(self) -> bytes:
        out = super().genkey()
        '''
            *Derived Implementation*
        '''
        return bytes(out)

    def loadkey(self, keys:bytes):
        super().loadkey(keys)
        '''
            *Derived Implementation*
        '''

    def _prepare_enc(self, padded:tuple[bytes, bytes]) -> dict[str, object]:
        '''
            *Derived Implementation*
        '''
        pass
    def _loop_enc(self, padded, params:dict[str, object], i:int) -> None:
        '''
            *Derived Implementation*
        '''
        pass
    def _prepare_dec(self, cipher:bytes, honest:bool) -> dict[str, object]:
        '''
            *Derived Implementation*
        '''
        pass
    def _loop_dec(self, cipher, params:dict[str, object], i:int) -> None:
        '''
            *Derived Implementation*
        '''
        pass