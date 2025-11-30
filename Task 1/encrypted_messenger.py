import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# filenames required by the lab
MESSAGE_FILE = "message.txt"
ENCRYPTED_MESSAGE_FILE = "encrypted_message.bin"
ENCRYPTED_AES_KEY_FILE = "aes_key_encrypted.bin"
DECRYPTED_MESSAGE_FILE = "decrypted_message.txt"
PRIVATE_KEY_FILE = "userA_private_key.pem"
PUBLIC_KEY_FILE = "userA_public_key.pem"


# -------- User A: RSA keys --------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # save private key
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # save public key
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("[User A] RSA key pair generated.")
    return private_key, public_key


def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# -------- AES helpers --------
def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256 CBC with PKCS7 padding. Returns iv + ciphertext."""
    iv = os.urandom(16)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    return iv + ciphertext


def aes_decrypt(iv_and_ciphertext: bytes, key: bytes) -> bytes:
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded_plaintext = dec.update(ciphertext) + dec.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


# -------- User B: encrypt --------
def user_b_encrypt():
    # if message.txt doesn't exist, create a default one
    if not os.path.exists(MESSAGE_FILE):
        with open(MESSAGE_FILE, "w", encoding="utf-8") as f:
            f.write("Hello from User B. This is a secret message.")

    with open(MESSAGE_FILE, "r", encoding="utf-8") as f:
        message_bytes = f.read().encode("utf-8")

    public_key = load_public_key()

    # random AES-256 key
    aes_key = os.urandom(32)

    # encrypt message with AES
    encrypted_message = aes_encrypt(message_bytes, aes_key)

    # encrypt AES key with RSA (User A's public key)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # save both
    with open(ENCRYPTED_MESSAGE_FILE, "wb") as f:
        f.write(encrypted_message)

    with open(ENCRYPTED_AES_KEY_FILE, "wb") as f:
        f.write(encrypted_aes_key)

    print("[User B] Message encrypted with AES-256.")
    print("[User B] AES key encrypted with RSA public key.")
    print(f"[User B] Saved {ENCRYPTED_MESSAGE_FILE}, {ENCRYPTED_AES_KEY_FILE}")


# -------- User A: decrypt --------
def user_a_decrypt():
    private_key = load_private_key()

    # decrypt AES key
    with open(ENCRYPTED_AES_KEY_FILE, "rb") as f:
        encrypted_aes_key = f.read()

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # decrypt message
    with open(ENCRYPTED_MESSAGE_FILE, "rb") as f:
        encrypted_message = f.read()

    decrypted = aes_decrypt(encrypted_message, aes_key)

    with open(DECRYPTED_MESSAGE_FILE, "w", encoding="utf-8") as f:
        f.write(decrypted.decode("utf-8"))

    print("[User A] AES key decrypted with RSA private key.")
    print("[User A] Message decrypted with AES key.")
    print(f"[User A] Saved {DECRYPTED_MESSAGE_FILE}")


# -------- main flow --------
if __name__ == "__main__":
    print("=== Step 1: User A generates RSA keys ===")
    if not (os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE)):
        generate_rsa_keys()
    else:
        print("[User A] Keys already exist, skipping generation.")

    print("\n=== Step 2: User B encrypts the message ===")
    user_b_encrypt()

    print("\n=== Step 3: User A decrypts the message ===")
    user_a_decrypt()

    print("\nDone.")
