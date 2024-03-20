import os
from .get_hash import get_hash

def get_sample_info(file):
    # Collects the name of the sample.
    filename = os.path.basename(file)

    # Collects the SHA256 of the sample.
    file_hash = get_hash(file)

    return filename, file_hash