import hashlib
import json
import os
import shutil

HASH_FILE = "hashes.json"
ORIGINAL_FILE = "original.txt"
TAMPERED_FILE = "tampered.txt"


def compute_hashes(path):
    data = open(path, "rb").read()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def save_hashes(h):
    with open(HASH_FILE, "w", encoding="utf-8") as f:
        json.dump(h, f, indent=4)


def load_hashes():
    with open(HASH_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def init_baseline():
    if not os.path.exists(ORIGINAL_FILE):
        with open(ORIGINAL_FILE, "w", encoding="utf-8") as f:
            f.write("This is the original file used for integrity checking.")
    original_hashes = compute_hashes(ORIGINAL_FILE)
    save_hashes({"original": original_hashes})
    if not os.path.exists(TAMPERED_FILE):
        shutil.copyfile(ORIGINAL_FILE, TAMPERED_FILE)
    print("[+] Baseline created.")
    print(f"[+] Hashes saved to {HASH_FILE}.")
    print(f"[+] Copy created as {TAMPERED_FILE}.")
    print("Now modify tampered.txt and run this script again to simulate tampering.")


def check_integrity():
    stored = load_hashes()["original"]
    if not os.path.exists(TAMPERED_FILE):
        print(f"[!] {TAMPERED_FILE} not found.")
        return
    current = compute_hashes(TAMPERED_FILE)

    print("Stored hashes (original.txt):")
    for k, v in stored.items():
        print(f"  {k}: {v}")

    print("\nCurrent hashes (tampered.txt):")
    for k, v in current.items():
        print(f"  {k}: {v}")

    changed = any(stored[k] != current[k] for k in stored.keys())
    if changed:
        print("\nIntegrity check: FAIL (file has been modified).")
    else:
        print("\nIntegrity check: PASS (file matches original).")


if __name__ == "__main__":
    if not os.path.exists(HASH_FILE):
        init_baseline()
    else:
        check_integrity()
