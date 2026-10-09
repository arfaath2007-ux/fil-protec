"""
File Protection Utility
A simple program that converts file content into a protected format
and restores it with password-controlled access.
"""

import sys
import os
import hashlib
import secrets
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_SIZE = 16
NONCE_SIZE = 12
ITERATIONS = 100_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit encryption key from a password and salt using PBKDF2."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)


def protect_file(file_path: str, password: str, output_path: str = None) -> str:
    """
    Encrypts a file into a protected format (.protected).
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        data = f.read()

    # Generate random salt and nonce
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    if not output_path:
        output_path = file_path + ".protected"

    # Write container: [Salt 16B] + [Nonce 12B] + [Ciphertext + Auth Tag]
    with open(output_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    return output_path


def restore_file(file_path: str, password: str, output_path: str = None) -> str:
    """
    Restores an encrypted file back to its original content.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        blob = f.read()

    if len(blob) < (SALT_SIZE + NONCE_SIZE + 16):
        raise ValueError("Invalid protected file: file is too short or corrupted.")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        data = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise PermissionError("Access denied! Incorrect password or file has been tampered with.")

    if not output_path:
        if file_path.endswith(".protected"):
            output_path = file_path[:-10]
            # Avoid overwriting original file if it still exists
            if os.path.exists(output_path):
                base, ext = os.path.splitext(output_path)
                output_path = f"{base}_restored{ext}"
        else:
            output_path = file_path + ".restored"

    with open(output_path, "wb") as f:
        f.write(data)

    return output_path


def interactive_menu():
    print("=" * 45)
    print("        FILE PROTECTION UTILITY")
    print("=" * 45)
    print("1. Protect a file (Encrypt)")
    print("2. Restore a file (Decrypt)")
    print("3. Exit")
    print("-" * 45)

    choice = input("Enter choice (1-3): ").strip()
    if choice == "1":
        file_path = input("Enter path of file to protect: ").strip(' "\'')
        password = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[ERROR] Passwords do not match.")
            return

        try:
            out = protect_file(file_path, password)
            print(f"[SUCCESS] File protected successfully!")
            print(f"Protected file saved to: {out}")
        except Exception as e:
            print(f"[ERROR] {e}")

    elif choice == "2":
        file_path = input("Enter path of protected file: ").strip(' "\'')
        password = getpass.getpass("Enter password: ")

        try:
            out = restore_file(file_path, password)
            print(f"[SUCCESS] File restored successfully!")
            print(f"Restored file saved to: {out}")
        except Exception as e:
            print(f"[ERROR] {e}")

    elif choice == "3":
        print("Goodbye!")
    else:
        print("Invalid choice.")


def main():
    if len(sys.argv) == 1:
        interactive_menu()
    elif len(sys.argv) >= 3 and sys.argv[1].lower() == "protect":
        file_path = sys.argv[2]
        password = sys.argv[3] if len(sys.argv) > 3 else getpass.getpass("Enter password: ")
        out = protect_file(file_path, password)
        print(f"[SUCCESS] Protected: {out}")
    elif len(sys.argv) >= 3 and sys.argv[1].lower() == "restore":
        file_path = sys.argv[2]
        password = sys.argv[3] if len(sys.argv) > 3 else getpass.getpass("Enter password: ")
        out = restore_file(file_path, password)
        print(f"[SUCCESS] Restored: {out}")
    else:
        print("Usage:")
        print("  py file_protector.py                     (Interactive Menu)")
        print("  py file_protector.py protect <file>      (CLI Protect)")
        print("  py file_protector.py restore <file>      (CLI Restore)")


if __name__ == "__main__":
    main()
