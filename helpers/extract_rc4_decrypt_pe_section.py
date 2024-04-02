import binascii
import pefile
from helpers.decrypt_rc4 import decrypt_rc4

'''

    Helper information:

        This helper is a implementation of the RC4 decryption of data into some PE Section.
        
        This implementation needs four arguments, the file path (sample), section name, key location (length) and encrypted data.

'''


def extract_rc4_decrypt_pe_section(file_path, section_name, key, enc_data):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Search for the desired section
        for section in pe.sections:
            if section.Name.decode().rstrip('\x00') == section_name:
                # Extract raw data
                raw_data = section.get_data()

                # Extract the key and the encrypted data
                key_data = raw_data[:key]
                remaining_data = raw_data[key:key + enc_data]

                # Convert to hexadecimal and print
                key_hex = binascii.hexlify(key_data).decode('utf-8')
                remaining_hex = binascii.hexlify(remaining_data).decode('utf-8')

                print(f"\n[!] Hex Key ({key} bytes): {key_hex}")
                print(f"\n[!] Hex Encrypted Data ({enc_data} bytes): {remaining_hex}")

                # Decrypt using RC4
                key = binascii.unhexlify(key_hex)
                encrypted_data = binascii.unhexlify(remaining_hex)
                decrypted_data = decrypt_rc4(key, encrypted_data)

                print("\n[+] Decrypted Data:")
                print('\n'.join(part.decode('latin-1') for part in decrypted_data.split(b'\x00') if part))
                break
        else:
            print(f"\n[-] Section '{section_name}' not found in the PE file. [-]")

    except Exception as e:
        print(f"\n[-] Error processing the PE file: {e} [-]")