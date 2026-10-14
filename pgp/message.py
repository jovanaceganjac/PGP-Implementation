import base64
import json
import time

from . import ciphers, rsa_keys

ARMOR_HEADER = "-----BEGIN PGP MESSAGE-----"
ARMOR_FOOTER = "-----END PGP MESSAGE-----"


class MessageError(Exception):
    pass


class ReceiveResult:
    def __init__(self, data, filename, encrypted, compressed, signed,
                 signature_valid, signer_user_id, signer_key_id):
        self.data = data
        self.filename = filename
        self.encrypted = encrypted
        self.compressed = compressed
        self.signed = signed
        self.signature_valid = signature_valid
        self.signer_user_id = signer_user_id
        self.signer_key_id = signer_key_id


def build_message(data, filename, sign_private_key=None, sign_key_id=None,
                  encrypt_public_key=None, encrypt_recipient_key_id=None,
                  cipher_name=None, compress=True, armor=True):
    message_content = {
        "message": {
            "filename": filename,
            "timestamp": int(time.time()),
            "data": base64.b64encode(data).decode("ascii"),
        },
        "signature": None,
    }

    if sign_private_key is not None:
        message_digest = ciphers.sha1(data)
        signature = rsa_keys.sign_digest(sign_private_key, message_digest)
        message_content["signature"] = {
            "timestamp": int(time.time()),
            "signer_key_id": sign_key_id,
            "leading_two_octets": message_digest[:2].hex(),
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    plaintext = json.dumps(message_content).encode("utf-8")

    if compress:
        plaintext = ciphers.compress(plaintext)

    envelope = {"compressed": compress, "encrypted": False}

    if encrypt_public_key is not None:
        session_key = ciphers.generate_session_key(cipher_name)
        iv, ciphertext = ciphers.symmetric_encrypt(cipher_name, session_key, plaintext)
        encrypted_session_key = rsa_keys.rsa_encrypt(encrypt_public_key, session_key)
        envelope["encrypted"] = True
        envelope["cipher"] = cipher_name
        envelope["session"] = {
            "recipient_key_id": encrypt_recipient_key_id,
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode("ascii"),
            "iv": base64.b64encode(iv).decode("ascii"),
        }
        envelope["payload"] = base64.b64encode(ciphertext).decode("ascii")
    else:
        envelope["payload"] = base64.b64encode(plaintext).decode("ascii")

    envelope_bytes = json.dumps(envelope).encode("utf-8")

    if armor:
        armored_text = ARMOR_HEADER + "\n\n" + ciphers.radix64_encode(envelope_bytes) + "\n" + ARMOR_FOOTER + "\n"
        return armored_text.encode("utf-8")
    return envelope_bytes


def parse_message(raw_bytes, find_private_by_id, find_public_by_id, get_passphrase):
    try:
        file_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise MessageError("Fajl nije prepoznat kao validna poruka.")

    file_text = file_text.strip()
    if file_text.startswith(ARMOR_HEADER):
        armor_body = file_text[len(ARMOR_HEADER):]
        footer_index = armor_body.find(ARMOR_FOOTER)
        if footer_index == -1:
            raise MessageError("Nedostaje kraj poruke.")
        armor_body = armor_body[:footer_index].strip()
        try:
            envelope_bytes = ciphers.radix64_decode(armor_body)
        except Exception:
            raise MessageError("Neuspesno radix-64 dekodiranje poruke.")
    else:
        envelope_bytes = raw_bytes

    try:
        envelope = json.loads(envelope_bytes)
    except Exception:
        raise MessageError("Fajl nije prepoznat kao validna PGP poruka.")

    if envelope.get("encrypted"):
        session_info = envelope["session"]
        cipher_name = envelope["cipher"]
        recipient_key_id = session_info["recipient_key_id"]

        recipient_entry = find_private_by_id(recipient_key_id)
        if recipient_entry is None:
            raise MessageError(
                "Ne postoji privatni kljuc za desifrovanje ove poruke."
            )

        passphrase = get_passphrase(recipient_entry)
        if passphrase is None:
            raise MessageError("Desifrovanje je otkazano.")

        try:
            recipient_private_key = rsa_keys.unlock_private_key(recipient_entry, passphrase)
        except ValueError as error:
            raise MessageError(str(error))

        try:
            encrypted_session_key = base64.b64decode(session_info["encrypted_session_key"])
            session_key = rsa_keys.rsa_decrypt(recipient_private_key, encrypted_session_key)
            iv = base64.b64decode(session_info["iv"])
            ciphertext = base64.b64decode(envelope["payload"])
            plaintext = ciphers.symmetric_decrypt(cipher_name, session_key, iv, ciphertext)
        except Exception:
            raise MessageError("Desifrovanje poruke nije uspelo.")
    else:
        plaintext = base64.b64decode(envelope["payload"])

    if envelope.get("compressed"):
        try:
            plaintext = ciphers.decompress(plaintext)
        except Exception:
            raise MessageError("Dekompresija poruke nije uspela.")

    try:
        message_content = json.loads(plaintext)
        message_info = message_content["message"]
        data = base64.b64decode(message_info["data"])
        filename = message_info["filename"]
    except Exception:
        raise MessageError("Sadrzaj poruke je ostecen.")

    signed = message_content.get("signature") is not None
    signature_valid = None
    signer_user_id = None
    signer_key_id = None

    if signed:
        signature_info = message_content["signature"]
        signer_key_id = signature_info["signer_key_id"]
        signer_entry = find_public_by_id(signer_key_id)
        if signer_entry is None:
            signature_valid = False
        else:
            signer_user_id = signer_entry.user_id
            message_digest = ciphers.sha1(data)
            signature_bytes = base64.b64decode(signature_info["signature"])
            signature_valid = rsa_keys.verify_digest(signer_entry.public_key(), message_digest, signature_bytes)

    return ReceiveResult(
        data=data,
        filename=filename,
        encrypted=bool(envelope.get("encrypted")),
        compressed=bool(envelope.get("compressed")),
        signed=signed,
        signature_valid=signature_valid,
        signer_user_id=signer_user_id,
        signer_key_id=signer_key_id,
    )
