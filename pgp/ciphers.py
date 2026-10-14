import base64
import hashlib
import os
import warnings
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

SUPPORTED_CIPHERS = ("AES128", "CAST5")

KEY_SIZES = {"AES128": 16, "CAST5": 16}
BLOCK_SIZES = {"AES128": 16, "CAST5": 8}


def generate_session_key(cipher_name):
    return os.urandom(KEY_SIZES[cipher_name])


def make_algorithm(cipher_name, session_key):
    if cipher_name == "AES128":
        return algorithms.AES(session_key)
    elif cipher_name == "CAST5":
        return algorithms.CAST5(session_key)


def symmetric_encrypt(cipher_name, session_key, plaintext):
    iv = os.urandom(BLOCK_SIZES[cipher_name])
    cipher = Cipher(make_algorithm(cipher_name, session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext


def symmetric_decrypt(cipher_name, session_key, iv, ciphertext):
    cipher = Cipher(make_algorithm(cipher_name, session_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def sha1(data):
    return hashlib.sha1(data).digest()


def compress(data):
    return zlib.compress(data)


def decompress(data):
    return zlib.decompress(data)


def radix64_encode(data):
    return base64.b64encode(data).decode("ascii")


def radix64_decode(encoded_text):
    return base64.b64decode(encoded_text)
