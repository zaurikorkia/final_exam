# Task 2 – Secure File Exchange Using RSA + AES

## 1. Scenario

Alice wants to send Bob a secret file securely.  
For this, a hybrid encryption scheme is used:
- RSA is used to encrypt the AES key (asymmetric encryption)
- AES-256 is used to encrypt the actual file (symmetric encryption)

---

## 2. Steps and Scripts

### 2.1 Key Generation (Bob) – `generate_keys.py`

1. Bob runs `generate_keys.py`.
2. The script creates an RSA key pair:
   - `private.pem` – Bob's private key  
   - `public.pem` – Bob's public key  
3. The public key is shared with Alice, while the private key remains only with Bob.

### 2.2 Encryption (Alice) – `task2_encrypt.py`

1. Alice prepares the plaintext file `alice_message.txt`.  
   If the file does not exist, the script creates it with a default message.
2. The script computes the SHA-256 hash of `alice_message.txt` and saves it in `sha256_original.txt`.
3. A random AES-256 key (32 bytes) is generated.
4. The file `alice_message.txt` is encrypted with AES-256 in CBC mode with PKCS7 padding.  
   The IV is stored together with the ciphertext in `encrypted_file.bin`.
5. The AES key is encrypted with Bob’s RSA public key using OAEP with SHA-256.  
   The encrypted AES key is saved to `aes_key_encrypted.bin`.

### 2.3 Decryption (Bob) – `task2_decrypt.py`

1. Bob loads his RSA private key from `private.pem`.
2. The script reads `aes_key_encrypted.bin` and decrypts it using Bob’s private key, recovering the original AES-256 key.
3. The script reads `encrypted_file.bin`, separates the IV and ciphertext, and decrypts the file using the recovered AES key.  
   The decrypted plaintext is saved as `decrypted_message.txt`.
4. The script computes the SHA-256 hash of `decrypted_message.txt` and compares it with the value stored in `sha256_original.txt`.  
   If the hashes match, the decrypted file is identical to the original and its integrity is confirmed.

---

## 3. AES vs RSA (Speed, Use Case, Security)

**AES (symmetric encryption)**  
- Very fast and efficient for encrypting large files and data streams.  
- Uses the same key for encryption and decryption.  
- In this task, AES is used to encrypt the content of the file.

**RSA (asymmetric encryption)**  
- Slower and not suitable for encrypting large files directly.  
- Uses a public key for encryption and a private key for decryption.  
- In this task, RSA is used only to protect the AES key.

**Hybrid encryption** combines both approaches:
- AES encrypts the actual data (file) efficiently.  
- RSA protects the AES key.  
Together they provide good performance and strong security for secure file exchange.