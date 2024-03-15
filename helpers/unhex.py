import binascii

def unhex(hex):
    if type(hex) == str:
        return binascii.unhexlify(hex.encode('utf-8'))
    else:
        return binascii.unhexlify(hex)