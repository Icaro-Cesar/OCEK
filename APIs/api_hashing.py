import requests


'''

    This script is a implementation of a simple request through HashDB API

'''


def api_hashing(hash_value,alg):
    response = requests.get(f'https://hashdb.openanalysis.net/hash/{alg}/{hash_value}')
    if response.ok:
        hashes = response.json().get('hashes', [])
        if len(hashes) != 0:
            strings_decript = hashes[0].get('string', {}).get('string', '')
            print(f"\033[32mDe-Hashed String: {hex(hash_value)} -> {strings_decript}\033[0m")
    else:
        print('\n\033[31m[+] Error on HashDB [+]\033[0m\n')