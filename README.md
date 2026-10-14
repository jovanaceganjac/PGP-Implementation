# PGP Implementation

A desktop application that implements the core of the PGP protocol: key management,
signing, encryption and their combination, following the OpenPGP message flow.
Built for the *Data Security* course at ETF Belgrade (team project, 2 students).

## Features

- **RSA key pairs** (1024 / 2048 bit) generated per user, private keys stored encrypted
  with a passphrase
- **Private and public key rings** with import / export in PEM format
- **Sending a message:** optional RSA signature (SHA-1), ZIP compression, symmetric
  encryption with **AES-128** or **CAST5** under a random session key, and Radix-64 encoding
- **Receiving a message:** automatic detection of each layer, decryption, signature
  verification and display of who signed it
- Tkinter GUI with separate tabs for keys, sending and receiving

## Tech

Python 3, [`cryptography`](https://cryptography.io/), Tkinter

## Run

```bash
pip install -r requirements.txt
python main.py
```

Key rings are created on first run in `keyrings/` (not tracked in git).

## Structure

```
pgp/        protocol logic: ciphers.py, rsa_keys.py, keyring_store.py, message.py
gui/        Tkinter tabs (keys, send, receive)
main.py     entry point
```
