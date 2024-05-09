
#   Title:  Binary Ninja Latrodectus String Decryptor Script
#   Reference: Script that helps a lot to understand the algorithm => https://github.com/leandrofroes/malware-research/blob/main/Latrodectus/binja_latrodectus_str_dec.py

def format_string(decrypted_data) -> str:
	wide = decrypted_data[1] == 0
	formated_string = ""

	if not wide:
		formated_string = decrypted_data.decode("utf8")
	else:
		formated_string = decrypted_data.decode("utf-16le")
		
	if formated_string.isascii():
		return formated_string
	
	return ""


def decrypt_string(data_enc: bytes, xor_key: int) -> str:
    decrypted_string = bytearray()
    for enc_data in data_enc:
        xor_key += 1
        print("XOR key +1:", hex(xor_key))
        decrypted_string.append(enc_data ^ (xor_key & 0xFF))
    return format_string(decrypted_string)

decrypt_function_address = # <= put here the address of the decrypt function
cross_references =  bv.get_code_refs(decrypt_function_address)
dec_strings = []

for xrefs in cross_references:
    encrypted_data = xrefs.mlil.params[0].constant   # Take the address of the encrypted data block
    encrypted_data_block = bv.read(encrypted_data, 6)
    decryption_key = encrypted_data_block[0]   # The XOR key is the first byte of the encrypted data block
    print("\nInitial Byte Key:", hex(decryption_key))
    data_lenght_calc = encrypted_data_block[0] ^ encrypted_data_block[4]    # data lenght calculation => The 1st byte of the data block ^ 5th byte of the data block
    encrypt_full_data_lenght = bv.read(encrypted_data, data_lenght_calc + 6)
    encrypted_data_only = encrypt_full_data_lenght[6:6+data_lenght_calc]    # Encrypted data block only, sixth byte and so on
    print("Encrypted Data Block:", encrypted_data_only)
    decrypted_str = decrypt_string(encrypted_data_only, decryption_key)
    bv.set_comment_at(xrefs.address, decrypted_str)          # Set comments on each Cross-Reference of the XOR Decryption function
    print("Decrypted String:", decrypted_str)
