import hashlib

def get_hash(file):
    # Creates an object in the variable sha256.
    sha256 = hashlib.sha256()

    # Opens the sample in byte-reading mode.
    with open(file, 'rb') as f:
        # Reads the raw data from the sample and collect the SHA256.
        for block in iter(lambda: f.read(4096), b''):
            sha256.update(block)

    # Returns the hash in hexadecimal format.
    return sha256.hexdigest()