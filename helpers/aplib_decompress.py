import struct
from classes import APLib
from binascii import crc32

# Implementação do algoritmo de compressão APlib
# Link de Referência: https://github.com/snemes/aplib/blob/master/src/aplib.py

def aplib_decompress(data, strict=False):
    packed_size = None
    packed_crc = None
    orig_size = None
    orig_crc = None
    if data.startswith(b'AP32') and len(data) >= 24:

        header_size, packed_size, packed_crc, orig_size, orig_crc = struct.unpack_from('=IIIII', data, 4)
        data = data[header_size : header_size + packed_size]
    if strict:
        if packed_size is not None and packed_size != len(data):
            raise RuntimeError('Packed data size is incorrect')
        if packed_crc is not None and packed_crc != crc32(data):
            raise RuntimeError('Packed data checksum is incorrect')
    result = APLib.APLib(data, strict=strict).depack()
    if strict:
        if orig_size is not None and orig_size != len(result):
            raise RuntimeError('Unpacked data size is incorrect')
        if orig_crc is not None and orig_crc != crc32(result):
            raise RuntimeError('Unpacked data checksum is incorrect')
    return result