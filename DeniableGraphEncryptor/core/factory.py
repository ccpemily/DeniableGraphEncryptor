from core.algorithm import elgamal, polynomial, serial
from core.encryptor import AbstractEncryptor
from typing import Type

class EncryptorFactory(object):
    '''
        Factory class to produce AbstractEncryptor.
    '''
    type_str:dict[str, Type[AbstractEncryptor]] = {
        "polynomial": polynomial.PolynomialEncryptor,
        "elgamal": elgamal.ElGamalEncryptor,
        "serial": serial.SerialEncryptor
    }
    
    @staticmethod
    def create(name:str, param:int):
        return EncryptorFactory.type_str[name](param)