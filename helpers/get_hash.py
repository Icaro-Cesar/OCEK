import hashlib

def get_hash(file):
    # Cria um objeto na variável sha256"
    sha256 = hashlib.sha256()

    # Abre o sample em modo de leitura de bytes
    with open(file, 'rb') as f:
        # Lê os dados bruto do sample e coleta o sha256
        for block in iter(lambda: f.read(4096), b''):
            sha256.update(block)

    # Retorna o hash em formato hexadecimal
    return sha256.hexdigest()