import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Run Encryptor.")

    parser.add_argument('-a', '--algorithm', nargs='?', default='polynomial',
                        help='Encryption and decryption algorithm')
    parser.add_argument('-b', '--bytes', type=int, default=32,
                        help='Bytewidth of encryption system')
    parser.add_argument('-i', '--inputdir', nargs='?', default='.\\data\\in',
                        help='Input data path.')
    parser.add_argument('-o', '--outputdir', nargs='?', default='.\\data\\out',
                        help='Output data path.')
    parser.add_argument('-t', '--interactive', action='store_true',
                        help='Enable interactive mode. When enabled, all the args below are ignored.')
    parser.add_argument('-eb', '--batchenc', action='store_true',
                        help='Automatically try to encrypt all file in inputdir with specified key.')
    parser.add_argument('-db', '--batchdec', action='store_true',
                        help='Automatically try to decrypt all file in inputdir with specified key.')
    parser.add_argument('-e', '--enc', nargs='?', default=None,
                        help='Plain file name to encrypt. Ignored when batchenc is enabled.')
    parser.add_argument('-d', '--dec', nargs='?', default=None,
                        help='Cipher file name to decrypt. Ignored when batchdec is enabled.')
    parser.add_argument('-y', '--deny', action='store_true',
                        help='Enable deniable encryption or dishonest decryption. Fake plains are specified with [filename] in inputdir/fake_plains/.')
    parser.add_argument('-k', '--key', nargs='?', default=None,
                        help='Key file name to store encryption key or load decryption key.')
    

    args = parser.parse_args()

    return args
