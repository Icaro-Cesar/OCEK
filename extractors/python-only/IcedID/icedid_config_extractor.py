import sys
sys.path.append('')     # <- Here you need to put the full path of the OCEK directory
from helpers.extract_rc4_decrypt_pe_section import extract_rc4_decrypt_pe_section


'''

    IcedID config extractor

    Author: 0x0d4y

'''


# Static information
section_name = ".data"
key_size = 8
enc_data = 248

while True:
    try:
        # Prompt the user for the PE file path
        pe_file_path = input("\n[+] Enter the IcedID file path (Ctrl+C to exit): ")

        # Call the function to extract and print section data
        extract_rc4_decrypt_pe_section(pe_file_path, section_name, key_size, enc_data)
        
    except KeyboardInterrupt:
        print("\n[!] Program terminated by user (Ctrl+C). Goodbye!")
        break
    except Exception as e:
        print(f"\n[-] An error occurred: {e} [-]")