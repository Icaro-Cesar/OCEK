import requests

def api_hashing(hash_value):
    response = requests.get(f'https://hashdb.openanalysis.net/hash/add_ror13/{hash_value}')
    if response.ok:
        hashes = response.json().get('hashes', [])
        if len(hashes) != 0:
            strings_decript = hashes[0].get('string', {}).get('string', '')
            print(f"\033[32mHash Decodificado: {hex(hash_value)} -> {strings_decript}\033[0m")
    else:
        print('\n\033[31m[+] Erro ao consultar hasdb [+]\033[0m\n')