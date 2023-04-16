import secrets
from threading import current_thread
from multiprocessing import current_process
from tqdm import tqdm

def random_padding(m:bytes, blockcount:int, blocksize:int) -> bytes:
    lm = len(m)
    m = bytearray(lm.to_bytes(4, 'big') + m)
    p = blocksize - len(m) % blocksize
    for i in range(p):
        m += secrets.randbits(8).to_bytes(1, 'big')
    r = blockcount - len(m) // blocksize
    if(r <= 0):
        return m
    for i in tqdm(range(r), desc=pformat('Padder', 'Padding...'), unit='Blocks', unit_scale=True):
        m += secrets.randbits(8 * blocksize).to_bytes(blocksize, 'big')
    return bytes(m)

def zero_padding(m:bytes, blockcount:int, blocksize:int) -> bytes:
    lm = len(m)
    m = bytearray(lm.to_bytes(4, 'big') + m)
    p = blocksize - len(m) % blocksize
    for i in range(p):
        m += int(0).to_bytes(1, 'big')
    r = blockcount - len(m) // blocksize
    if(r <= 0):
        return m
    for i in tqdm(range(r), desc=pformat('Padder', 'Padding...'), unit='Blocks', unit_scale=True):
        m += int(0).to_bytes(blocksize, 'big')
    return bytes(m)

def unpad(m:bytes) -> bytes:
    l = int.from_bytes(m[0:4], 'big')
    return m[4:l + 4]

def pformat(src:str, content:str) -> str:
    pname = current_process().name
    tname = ''
    if(pname == 'MainProcess'):
        tname = current_thread().name
    elif(pname[0:12] == 'SpawnProcess'):
        lst = pname.split('-')
        tname = 'WorkerThread/' + lst[1]
    return '[' + tname + '/' + src + ']' + content