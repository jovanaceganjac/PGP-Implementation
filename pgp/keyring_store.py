import json
import os
import time

from . import rsa_keys

class KeyringError(Exception):
    pass

class PublicKeyEntry:
    def __init__(self, timestamp, key_id, public_key_pem, user_id):
        self.timestamp = timestamp
        self.key_id = key_id
        self.public_key_pem = public_key_pem
        self.user_id = user_id

    def public_key(self):
        return rsa_keys.public_key_from_pem(self.public_key_pem.encode("utf-8"))

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "user_id": self.user_id,
        }


class PrivateKeyEntry:
    def __init__(self, timestamp, key_id, public_key_pem, encrypted_private_key, user_id, key_size):
        self.timestamp = timestamp
        self.key_id = key_id
        self.public_key_pem = public_key_pem
        self.encrypted_private_key = encrypted_private_key
        self.user_id = user_id
        self.key_size = key_size

    def public_key(self):
        return rsa_keys.public_key_from_pem(self.public_key_pem.encode("utf-8"))

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "encrypted_private_key": self.encrypted_private_key,
            "user_id": self.user_id,
            "key_size": self.key_size,
        }


class KeyringManager:
    def __init__(self, storage_dir="keyrings"):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
        self.private_path = os.path.join(storage_dir, "private_keyring.json")
        self.public_path = os.path.join(storage_dir, "public_keyring.json")
        self.private_entries = []
        self.public_entries = []
        self.load()

    def load(self):
        if os.path.exists(self.private_path):
            with open(self.private_path, "r", encoding="utf-8") as file:
                for record in json.load(file):
                    self.private_entries.append(PrivateKeyEntry(**record))
        if os.path.exists(self.public_path):
            with open(self.public_path, "r", encoding="utf-8") as file:
                for record in json.load(file):
                    self.public_entries.append(PublicKeyEntry(**record))

    def save_private(self):
        with open(self.private_path, "w", encoding="utf-8") as file:
            json.dump([entry.to_dict() for entry in self.private_entries], file, indent=2)

    def save_public(self):
        with open(self.public_path, "w", encoding="utf-8") as file:
            json.dump([entry.to_dict() for entry in self.public_entries], file, indent=2)

    def find_private(self, key_id):
        for entry in self.private_entries:
            if entry.key_id == key_id:
                return entry
        return None

    def find_public(self, key_id):
        for entry in self.public_entries:
            if entry.key_id == key_id:
                return entry
        return None

    def generate_keypair(self, name, email, key_size, passphrase):
        private_key = rsa_keys.generate_keypair(key_size)
        public_key = private_key.public_key()
        key_id = rsa_keys.compute_key_id(public_key)
        public_key_pem = rsa_keys.public_key_to_pem(public_key).decode("utf-8")
        private_key_pem = rsa_keys.private_key_to_pem(private_key)
        encrypted_private_key = rsa_keys.encrypt_private_key_pem(private_key_pem, passphrase)

        new_entry = PrivateKeyEntry(
            timestamp=int(time.time()),
            key_id=key_id,
            public_key_pem=public_key_pem,
            encrypted_private_key=encrypted_private_key,
            user_id=name + " <" + email + ">",
            key_size=key_size,
        )
        self.private_entries.append(new_entry)
        self.save_private()
        self.copy_to_public_ring(new_entry)
        return new_entry

    def copy_to_public_ring(self, private_entry):
        if self.find_public(private_entry.key_id):
            return
        new_entry = PublicKeyEntry(
            timestamp=private_entry.timestamp,
            key_id=private_entry.key_id,
            public_key_pem=private_entry.public_key_pem,
            user_id=private_entry.user_id,
        )
        self.public_entries.append(new_entry)
        self.save_public()

    def delete_private(self, key_id):
        for entry in list(self.private_entries):
            if entry.key_id == key_id:
                self.private_entries.remove(entry)
        self.save_private()

    def delete_public(self, key_id):
        for entry in list(self.public_entries):
            if entry.key_id == key_id:
                self.public_entries.remove(entry)
        self.save_public()

    def add_public_entry(self, public_key_pem, user_id):
        public_key = rsa_keys.public_key_from_pem(public_key_pem.encode("utf-8"))
        key_id = rsa_keys.compute_key_id(public_key)
        if self.find_public(key_id):
            raise KeyringError("Ovaj javni kljuc vec postoji u prstenu.")
        new_entry = PublicKeyEntry(
            timestamp=int(time.time()),
            key_id=key_id,
            public_key_pem=public_key_pem,
            user_id=user_id,
        )
        self.public_entries.append(new_entry)
        self.save_public()
        return new_entry

    def export_public_key(self, key_id, dest_path):
        found_entry = self.find_private(key_id)
        if found_entry is None:
            found_entry = self.find_public(key_id)
        if found_entry is None:
            raise KeyringError("Kljuc nije pronadjen.")
        file_content = "# User-ID: " + found_entry.user_id + "\n"
        file_content += "# Key-ID: " + found_entry.key_id + "\n"
        file_content += found_entry.public_key_pem.strip() + "\n"
        with open(dest_path, "w", encoding="utf-8") as file:
            file.write(file_content)

    def export_keypair(self, key_id, dest_path, unlock_passphrase, export_passphrase):
        found_entry = self.find_private(key_id)
        if found_entry is None:
            raise KeyringError("Privatni kljuc nije pronadjen u prstenu.")
        private_key = rsa_keys.unlock_private_key(found_entry, unlock_passphrase)
        encrypted_private_pem = rsa_keys.private_key_to_pem_encrypted(private_key, export_passphrase).decode("utf-8")
        file_content = "# User-ID: " + found_entry.user_id + "\n"
        file_content += "# Key-ID: " + found_entry.key_id + "\n"
        file_content += found_entry.public_key_pem.strip() + "\n"
        file_content += encrypted_private_pem.strip() + "\n"
        with open(dest_path, "w", encoding="utf-8") as file:
            file.write(file_content)

    def parse_pem_file(self, file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            file_content = file.read()

        user_id = None
        for line in file_content.splitlines():
            if line.startswith("# User-ID:"):
                user_id = line[len("# User-ID:"):].strip()

        public_key_pem = self.extract_block(file_content, "-----BEGIN PUBLIC KEY-----",
                                            "-----END PUBLIC KEY-----")
        private_key_pem = self.extract_block(file_content, "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                                             "-----END ENCRYPTED PRIVATE KEY-----")
        return user_id, public_key_pem, private_key_pem

    def extract_block(self, text, begin_marker, end_marker):
        begin_index = text.find(begin_marker)
        if begin_index == -1:
            return None
        end_index = text.find(end_marker, begin_index)
        if end_index == -1:
            return None
        return text[begin_index:end_index + len(end_marker)]

    def import_public_key_file(self, file_path, user_id=None):
        parsed_user_id, public_key_pem, private_key_pem = self.parse_pem_file(file_path)
        if public_key_pem is None:
            raise KeyringError("Fajl ne sadrzi validan javni kljuc.")
        final_user_id = user_id or parsed_user_id
        if not final_user_id:
            raise KeyringError("Nedostaje User-ID za javni kljuc koji se uvozi.")
        return self.add_public_entry(public_key_pem, final_user_id)

    def import_keypair_file(self, file_path, pem_passphrase, keyring_passphrase, user_id=None):
        parsed_user_id, public_key_pem, private_key_pem = self.parse_pem_file(file_path)
        if public_key_pem is None or private_key_pem is None:
            raise KeyringError("Fajl ne sadrzi kompletan par kljuceva.")
        final_user_id = user_id or parsed_user_id
        if not final_user_id:
            raise KeyringError("Nedostaje User-ID za par kljuceva koji se uvozi.")

        try:
            private_key = rsa_keys.private_key_from_pem(private_key_pem.encode("utf-8"), pem_passphrase)
        except Exception:
            raise KeyringError("Pogresna lozinka fajla.")

        public_key = rsa_keys.public_key_from_pem(public_key_pem.encode("utf-8"))
        key_id = rsa_keys.compute_key_id(public_key)
        if self.find_private(key_id):
            raise KeyringError("Ovaj par kljuceva vec postoji u prstenu.")

        decrypted_private_pem = rsa_keys.private_key_to_pem(private_key)
        encrypted_private_key = rsa_keys.encrypt_private_key_pem(decrypted_private_pem, keyring_passphrase)

        new_entry = PrivateKeyEntry(
            timestamp=int(time.time()),
            key_id=key_id,
            public_key_pem=public_key_pem,
            encrypted_private_key=encrypted_private_key,
            user_id=final_user_id,
            key_size=private_key.key_size,
        )
        self.private_entries.append(new_entry)
        self.save_private()
        self.copy_to_public_ring(new_entry)
        return new_entry
