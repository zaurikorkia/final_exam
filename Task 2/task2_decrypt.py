import hashlib

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

PRIVATE_KEY_FILE = "private.pem"
ENCRYPTED_FILE = "encrypted_file.bin"
ENCRYPTED_AES_KEY_FILE = "aes_key_encrypted.bin"
DECRYPTED_MESSAGE_FILE = "decrypted_message.txt"
SHA256_ORIGINAL_FILE = "sha256_original.txt"


def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def aes_decrypt(iv_and_ciphertext: bytes, key: bytes) -> bytes:
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def main():
    # 1) Load Bob's private key
    private_key = load_private_key()

    # 2) Load and decrypt AES key
    with open(ENCRYPTED_AES_KEY_FILE, "rb") as f:
        enc_aes_key = f.read()

    aes_key = private_key.decrypt(
        enc_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
            ),
    )
    print("[+] AES key decrypted using Bob's private RSA key.")

    # 3) Decrypt file with AES key
    with open(ENCRYPTED_FILE, "rb") as f:
        enc_data = f.read()

    decrypted = aes_decrypt(enc_data, aes_key)
    with open(DECRYPTED_MESSAGE_FILE, "wb") as f:
        f.write(decrypted)
    print(f"[+] File decrypted and saved as {DECRYPTED_MESSAGE_FILE}")

    # 4) Verify SHA-256 hash
    with open(SHA256_ORIGINAL_FILE, "r", encoding="utf-8") as f:
        original_hash = f.read().strip()

    new_hash = hashlib.sha256(decrypted).hexdigest()

    if new_hash == original_hash:
        print("[✓] SHA-256 verified: decrypted file matches original.")
    else:
        print("[!] SHA-256 mismatch: file was modified!")

    print("[✓] Decryption step finished.")


if __name__ == "__main__":
    main()
