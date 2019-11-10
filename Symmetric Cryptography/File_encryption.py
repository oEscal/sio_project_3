from utils import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def file_encryption(
    user_file, encrypted_file, encryption_algorithm, hash_algorithm="SHA256"
):

    params = cipher_params(encryption_algorithm, hash_algorithm)

    f = open(user_file, "r")
    file_content = f.read()
    file_length = len(file_content)
    f.close()

    cipher = Cipher(
        params["algorithm"], modes.CBC(params["iv"]), backend=default_backend()
    )

    iv_length = params["iv_length"]
    block_size = 1024 ** 2 * 4096
    padding_length = (iv_length - (file_length % iv_length)) % iv_length
    file_content += padding_length * "\x00"

    encryptor = cipher.encryptor()
    ct = str.encode("")
    for padding in range(0, file_length, block_size):
        ct += encryptor.update(str.encode(file_content[padding : padding + block_size]))
    ct = ct + encryptor.finalize()

    symmetric_protocol = Symmetric_protocol(
        params["iv"], params["salt"], padding_length, ct
    )

    cryptogram_file = open(encrypted_file, "wb")
    write_protocol(symmetric_protocol, cryptogram_file)
    cryptogram_file.close()
