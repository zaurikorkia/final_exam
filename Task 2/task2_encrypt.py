import os
import hashlib

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

PUBLIC_KEY_FILE = "public.pem"
ALICE_MESSAGE_FILE = "alice_message.txt"
ENCRYPTED_FILE = "encrypted_file.bin"
ENCRYPTED_AES_KEY_FILE = "aes_key_encrypted.bin"
SHA256_ORIGINAL_FILE = "sha256_original.txt"


def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256 CBC, PKCS7 padding. Returns iv + ciphertext."""
    iv = os.urandom(16)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext


def main():
    # 1) Make sure alice_message.txt exists
    if not os.path.exists(ALICE_MESSAGE_FILE):
        with open(ALICE_MESSAGE_FILE, "w", encoding="utf-8") as f:
            f.write("Hello Bob, this is a secret file from Alice.")

    with open(ALICE_MESSAGE_FILE, "rb") as f:
        plaintext = f.read()

    # 2) Compute and save SHA-256 hash of original file
    sha256 = hashlib.sha256(plaintext).hexdigest()
    with open(SHA256_ORIGINAL_FILE, "w", encoding="utf-8") as f:
        f.write(sha256)
    print(f"[+] Original SHA-256 saved to {SHA256_ORIGINAL_FILE}")

    # 3) Generate random AES-256 key
    aes_key = os.urandom(32)

    # 4) Encrypt file with AES
    encrypted_data = aes_encrypt(plaintext, aes_key)
    with open(ENCRYPTED_FILE, "wb") as f:
        f.write(encrypted_data)
    print(f"[+] File encrypted with AES and saved as {ENCRYPTED_FILE}")

    # 5) Encrypt AES key with Bob's public RSA key
    public_key = load_public_key()
    enc_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    with open(ENCRYPTED_AES_KEY_FILE, "wb") as f:
        f.write(enc_aes_key)
    print(f"[+] AES key encrypted with RSA and saved as {ENCRYPTED_AES_KEY_FILE}")

    print("[✓] Encryption step finished.")


if __name__ == "__main__":
    main()
