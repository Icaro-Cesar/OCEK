import arc4

'''

    Helper information:

        This helper is a implementation of the RC4 decryption

'''

def decrypt_rc4(key, encrypt_data):
    arc4_cipher = arc4.ARC4(key)
    return arc4_cipher.decrypt(encrypt_data)