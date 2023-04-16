from core.encryptor import AbstractEncryptor
from core.factory import EncryptorFactory
from core.utils import pformat
from imageapi.loader import IOManager
from ui.parser import parse_args

from concurrent.futures import ProcessPoolExecutor
import os
import os.path as pth


def batch_enc_handler(enc:AbstractEncryptor, plains:tuple[bytes, bytes]) -> bytes:
        return enc.encrypt(plains)

def batch_dec_handler(enc:AbstractEncryptor, cipher:bytes, deny:bool) -> bytes:
        return enc.decrypt(cipher, deny)
    

if __name__ == "__main__":
    #Argparse & io manager
    args = parse_args()
    #print(args)
    deny = args.deny or True
    io_in = IOManager(args.inputdir)
    io_out = IOManager(args.outputdir)

    #Initialize encryptor
    enc = EncryptorFactory.create(args.algorithm, args.bytes)
    keyname = "dkey.sk" if args.key == None else args.key

    #Multiprocess pool
    batch_pool = ProcessPoolExecutor(max_workers=12)

    if(args.batchenc):
        #Batch encrypt
        key = enc.genkey()
        enc.loadkey(key)
        dlist = os.listdir(io_in.root)
        flist = [f for f in dlist if pth.isfile(pth.join(io_in.root, f))]
        rlist = []
        if len(flist) == 0:
            print(pformat('Error', 'No file existence to encrypt.'))
        for fl in flist:
            fake = None if (not pth.isfile(pth.join(io_in.root, pth.basename(fl)))) or not deny else pth.basename(fl)
            plain = io_in.load_binary(fl)
            fplain = bytes() if fake == None else io_in.load_binary('fake_plains' + os.sep + fake)
            rlist.append((pth.basename(fl), batch_pool.submit(batch_enc_handler, enc, (plain, fplain))))
        batch_pool.shutdown(wait=True)
        for r in rlist:
            io_out.save_binary(r[0] + '.enc', r[1].result())
        io_out.save_binary(keyname, key)
        enc.flushkey()
    elif(args.enc != None):
        #Single encrypt
        key = enc.genkey()
        enc.loadkey(key)
        pfile = args.enc
        if not pth.isfile(pth.join(io_in.root, pfile)):
            print(pformat('Error', 'File not found: ' + pfile))
            exit(-1)
        fake = None if (not pth.isfile(pth.join(io_in.root, pth.basename(pfile)))) or not deny else pth.basename(pfile)
        plain = io_in.load_binary(pfile)
        fplain = bytes() if fake == None else io_in.load_binary('fake_plains' + os.sep + fake)
        cipher = enc.encrypt((plain, fplain))
        io_out.save_binary(pfile + '.enc', cipher)
        io_out.save_binary(keyname, key)
        enc.flushkey()


    elif(args.batchdec or True):
        #Batch decrypt
        key = io_in.load_binary(keyname)
        enc.loadkey(key)
        dlist = os.listdir(io_in.root)
        flist = [f for f in dlist if (pth.isfile(pth.join(io_in.root, f)) and (f != keyname) and (f[-4:-1] + f[-1] == '.enc'))]
        rlist = []
        if len(flist) == 0:
            print(pformat('Error', 'No file existence to decrypt.'))
        for fl in flist:
            cipher = io_in.load_binary(fl)
            rlist.append((pth.basename(fl), batch_pool.submit(batch_dec_handler, enc, cipher, deny)))
        batch_pool.shutdown(wait=True)
        for r in rlist:
            res = r[1].result()
            io_out.save_binary(r[0][0:-4], res)
        enc.flushkey()
    elif(args.dec != None):
        #Single decrypt
        key = io_in.load_binary(keyname)
        enc.loadkey(key)
        pfile = args.dec
        if not pth.isfile(pth.join(io_in.root, pfile)):
            print(pformat('Error', 'File not found: ' + pfile))
            exit(-1)
        cipher = io_in.load_binary(pfile)
        enc.flushkey()
