import sys
sys.path.append('/home/researcher/Projects/OCEK')
from helpers.tohex import tohex
from helpers.get_pe_section import get_pe_section

def decrypt(data, key):

  counter = 0
  output = bytearray(len(data))
  while counter < 0x20:
    keystream = data[counter:] + key
    byte_decrypted = keystream[0x40] ^ keystream[0]
    output[counter + 0x40 - len(key)] = byte_decrypted
    counter += 1
  return output

filepath = input("\nPut the IcedID x64 DLL filepath: ")
data = input("Put the PE section: ")

payload = get_pe_section(filepath, data)

decrypted_data = decrypt(payload, payload)

print("\nHex Input Decrypted:", decrypted_data.hex())
print("ASCII Output Decrypted:", decrypted_data.decode("ascii", errors="ignore"))
print("")