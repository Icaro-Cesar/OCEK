import binascii

'''

    Helper information:

        This helper is a implementation of a unhex strings

'''

def unhex(hex):
    if type(hex) == str:
        return binascii.unhexlify(hex.encode('utf-8'))
    else:
        return binascii.unhexlify(hex)