# This script it's inspired by the Leandro work.
# link => https://github.com/leandrofroes/malware-research/blob/main/Latrodectus/binja_latrodectus_str_dec.py

import pefile

def format_string(encoded_string: bytes) -> str:
    try:
        formated_string = encoded_string.decode('utf-8')
        if formated_string.isascii():
            return formated_string
    except UnicodeDecodeError:
        pass

    return "Not an ASCII String"

# Latrodectus String Decryption Algorithm
def decrypt_string(data_enc: bytes, xor_key: int) -> str:
    decrypted_strings = bytearray()
    for enc_data in data_enc:
        xor_key += 1
	print(hex("XOR Byte Key:", xor_key))	# Just to show the XOR Keys to each byte, for studying the algorithm
        decrypted_strings.append(enc_data ^ (xor_key & 0xFF))
    return format_string(decrypted_strings)

pe = pefile.PE("") # <= Put here the latrodectus sample full path

# In all Latrodectus sample, the first byte of the .data section, is the Initial XOR key.
# Below we collect this first byte
data_section = next((s for s in pe.sections if b'.data' in s.Name), None)
data = data_section.get_data()
first_data_byte = data[0]
references = []
for section in pe.sections:
    if b'.data' in section.Name:
        data = section.get_data()
        index = data.find(first_data_byte)
        while index != -1:
            references.append(section.VirtualAddress + index)
            index = data.find(first_data_byte, index + 1)

for ref in references:
    encryption_key = pe.get_data(ref, 1)[0]
    print("\033[33m\nXOR Initial Key: \033[0m", hex(encryption_key))
    data_length = encryption_key ^ pe.get_data(ref + 4, 1)[0]		# Calculate the lenght of the data
    print("\033[34mEncrypted Data Block Lenght: \033[0m", data_length)
    encrypted_data = pe.get_data(ref, data_length + 6)[6:]		# Jump six bytes to the initial encrypted block
    print("\033[31mEncrypted Data Block: \033[0m", hex(int.from_bytes(encrypted_data)))
    decrypted_str = decrypt_string(encrypted_data, encryption_key)	# Decrypt the strings
    print("\033[32mDecrypted String:\033[0m", decrypted_str)

pe.close()
