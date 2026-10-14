import base64
import hashlib
import os
import warnings

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


def generate_keypair(key_size):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def compute_key_id(public_key):
    n = public_key.public_numbers().n
    return format(n % (2 ** 64), "016X")


def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_pem(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)


def private_key_to_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_to_pem_encrypted(private_key, passphrase):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )


def private_key_from_pem(pem_bytes, passphrase=None):
    if passphrase:
        password = passphrase.encode("utf-8")
    else:
        password = None
    return serialization.load_pem_private_key(pem_bytes, password=password)


def encrypt_private_key_pem(private_key_pem, passphrase):
    key = hashlib.sha1(passphrase.encode("utf-8")).digest()[:16]
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
    ciphertext = encryptor.update(private_key_pem) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode("ascii")


def decrypt_private_key_pem(encrypted_data, passphrase):
    raw = base64.b64decode(encrypted_data)
    iv = raw[:16]
    ciphertext = raw[16:]
    key = hashlib.sha1(passphrase.encode("utf-8")).digest()[:16]
    decryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def unlock_private_key(entry, passphrase):
    try:
        pem_bytes = decrypt_private_key_pem(entry.encrypted_private_key, passphrase)
        return serialization.load_pem_private_key(pem_bytes, password=None)
    except Exception:
        raise ValueError("Pogresna lozinka za privatni kljuc.")


def rsa_encrypt(public_key, data):
    return public_key.encrypt(data, padding.PKCS1v15())


def rsa_decrypt(private_key, data):
    return private_key.decrypt(data, padding.PKCS1v15())


def sign_digest(private_key, digest):
    return private_key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA1()))


def verify_digest(public_key, digest, signature):
    try:
        public_key.verify(signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA1()))
        return True
    except InvalidSignature:
        return False
