import binascii

'''

    Helper information:

        This helper is a implementation of the transformation of data into hex values

'''

def tohex(data):
    if type(data) == str:
        return binascii.hexlify(data.encode('utf-8'))
    else:
        return binascii.hexlify(data)