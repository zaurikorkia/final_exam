# Encrypted Messaging App – Encryption Flow

This mini project shows how two users (User A and User B) can send an encrypted message using **RSA** and **AES** together.

- RSA is used for encrypting the AES key (public/private keys).
- AES is used for encrypting the actual message (fast symmetric encryption).

Main Python script: **encrypted_messenger.py**
Generated files:

- `message.txt`
- `encrypted_message.bin`
- `aes_key_encrypted.bin`
- `decrypted_message.txt`
- `userA_private_key.pem`
- `userA_public_key.pem`

---

## 2. Step 1 – User A generates RSA keys

Function: `generate_rsa_keys()`

1. User A generates an RSA key pair (2048-bit).
2. The **private key** is saved to: `userA_private_key.pem`
3. The **public key** is saved to: `userA_public_key.pem`
4. The public key can be shared with User B. The private key stays only with User A.

This is done automatically when we run `encrypted_messenger.py` if the key files do not exist.

---

## 3. Step 2 – User B encrypts the message

Function: `user_b_encrypt()`

1. The program checks if `message.txt` exists.
   - If not, it creates `message.txt` with a default secret message.
2. The content of `message.txt` is read as plaintext.
3. A random **AES-256 key** is generated (32 bytes).
4. The plaintext message is encrypted with AES-256 in **CBC mode** with **PKCS7 padding**.
   - The IV (initialization vector) is random.
   - The IV is stored together with the ciphertext in one file.
   - Result is written to: `encrypted_message.bin`
5. The AES key itself is encrypted using **User A’s RSA public key** with **OAEP + SHA-256**.
   - Result is written to: `aes_key_encrypted.bin`

At this point:

- `encrypted_message.bin` contains the AES-encrypted message.
- `aes_key_encrypted.bin` contains the RSA-encrypted AES key.

An attacker who sees only these two `.bin` files cannot read the message without User A’s private RSA key.

---

## 4. Step 3 – User A decrypts the message

Function: `user_a_decrypt()`

1. User A loads the RSA private key from `userA_private_key.pem`.
2. The program reads `aes_key_encrypted.bin` and decrypts it with the RSA private key.
   - This recovers the original AES-256 key.
3. The program reads `encrypted_message.bin`, separates the IV and ciphertext, and decrypts it with the recovered AES key.
4. The decrypted plaintext is saved into: `decrypted_message.txt`.

Now `decrypted_message.txt` should contain the same text as `message.txt`.

---

## 5. Final Result

- `message.txt` – original plaintext message.
- `encrypted_message.bin` – message encrypted with AES-256.
- `aes_key_encrypted.bin` – AES key encrypted with RSA (User A’s public key).
- `decrypted_message.txt` – message decrypted again by User A using the recovered AES key.

This shows a simple hybrid encryption system:
- RSA is used to protect the AES key.
- AES is used to protect the actual message.
