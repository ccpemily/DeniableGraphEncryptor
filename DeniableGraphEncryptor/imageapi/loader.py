import cv2
import os
import numpy as np
from core.utils import pformat


class IOManager(object):
    '''
    Class IOManager
    Loader for reading image data from disk.
    API:
        load(str) -> np.array
        load_bytes(str) -> np.array
        load_binary(str) -> bytes
        save_binary(str, bytes) -> None
    '''
    def __init__(self, root=None):
        '''
        Initialize a new instance of ImageLoader.
        root: The root folder to load image, default to current path.
        return: An ImageLoader instance.
        exception: FileNotFoundError.
    '''
        if(root == "" or root == None):
            self.root = os.path.abspath(".") + os.sep
            return
        try:
            if(os.path.exists(root)):
                self.root = root + os.sep
            else:
                raise FileNotFoundError(root)
        except FileNotFoundError:
            print(pformat("Fatal", "Path does not exist: " + root))
            self.root = os.path.abspath(".") + os.sep

    '''
    Load an image into memory.
    filename: Name of image file, automatically concatenated with root path.
    return: A 3-Dimension arraylist, formed as array[x, y, w]. x - Image height, y - Image width, w - Image channels.
    exception: FileNotFoundError.
    '''
    def load(self, filename:str):
        pth = self.root + filename
        try:
            if(not os.path.isfile(pth)):
                raise FileNotFoundError(filename)
        except FileNotFoundError:
            print(pformat("Fatal", "File not found: " + filename))
            return None
        return cv2.imread(pth)

    '''
    Load an image into memory as byte array.
    filename: Name of image file, automatically concatenated with root path.
    return: A bytearray, formed as array[x * y * w + 9]. x - Image height, y - Image width, w - Image channels.
    exception: FileNotFoundError.
    '''
    def load_bytes(self, filename:str):
        f = self.load(filename)
        h, w, c = f.shape
        f = f.flatten().tolist()
        f.insert(0, c % 256)
        for i in range(4):
            f.insert(0, w % 256)
            w //= 256
        for i in range(4):
            f.insert(0, h % 256)
            h //= 256
        return f

    def bytes_to_img(self, blist:list):
        h = 0
        w = 0
        c = 0
        for i in range(4):
            h <<= 8
            h += blist[i]
        for i in range(4):
            w <<= 8
            w += blist[i + 4]
        c = blist[8]
        blist = blist[9:]
        return np.array(blist, dtype=np.uint8).reshape((h, w, c))

    def load_binary(self, filename:str) -> bytes:
        pth = self.root + filename
        try:
            if(not os.path.isfile(pth)):
                raise FileNotFoundError(filename)
        except FileNotFoundError:
            print(pformat("Fatal", "File not found: " + filename))
            return None
        f = open(pth, 'rb')
        b = f.read()
        f.close()
        return b

    def save_binary(self, filename:str, data:bytes):
        pth = self.root + filename
        try:
            if(os.path.isfile(pth)):
                raise FileExistsError()
        except FileExistsError:
            print(pformat("Warn", "File already exists, will be overrided: " + filename))
        f = open(pth, 'wb')
        f.write(data)
        f.close()