import os
from .get_hash import get_hash

def get_sample_info(file):
    # Coleta o nome do sample
    filename = os.path.basename(file)

    # Coleta o sha256 do sample
    file_hash = get_hash(file)

    return filename, file_hash