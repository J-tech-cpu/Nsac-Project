import base64
from Crypto.Cipher import AES, PKCS1_OAEP, Blowfish, DES3, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
import sys

# Constants
AES_BLOCK_SIZE = 16
BLOWFISH_BLOCK_SIZE = Blowfish.block_size
TRIPLE_DES_BLOCK_SIZE = DES3.block_size
CHACHA20_NONCE_SIZE = 12  # Must be 12 bytes

def aes_decrypt(cipher_text: str):
    try:
        data = base64.b64decode(cipher_text)
        if len(data) < AES_BLOCK_SIZE:
            raise ValueError("Ciphertext too short for AES-CBC")
        iv = data[:AES_BLOCK_SIZE]
        ct = data[AES_BLOCK_SIZE:]
        key_hex = input("Enter the AES key (64 hex chars = 32 bytes): ").strip()
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            raise ValueError("AES key must be 32 bytes (64 hex characters)")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ct)
        pt = unpad(padded, AES_BLOCK_SIZE)
        return pt.decode(), "AES (CBC)"
    except Exception as e:
        raise ValueError(f"AES decryption failed: {e}")

def rsa_decrypt(cipher_text: str):
    try:
        private_key_pem = input("Enter the RSA private key (PEM format): ").strip()
        key = RSA.import_key(private_key_pem)
        cipher_rsa = PKCS1_OAEP.new(key)
        ct = base64.b64decode(cipher_text)
        pt = cipher_rsa.decrypt(ct)
        return pt.decode(), "RSA (OAEP)"
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {e}")

def blowfish_decrypt(cipher_text: str):
    try:
        data = base64.b64decode(cipher_text)
        if len(data) < BLOWFISH_BLOCK_SIZE:
            raise ValueError("Ciphertext too short for Blowfish-CBC")
        iv = data[:BLOWFISH_BLOCK_SIZE]
        ct = data[BLOWFISH_BLOCK_SIZE:]
        key_hex = input("Enter the Blowfish key (32 hex chars = 16 bytes): ").strip()
        key = bytes.fromhex(key_hex)
        if len(key) != 16:
            raise ValueError("Blowfish key must be 16 bytes (32 hex characters)")
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        padded = cipher.decrypt(ct)
        pt = unpad(padded, BLOWFISH_BLOCK_SIZE)
        return pt.decode(), "Blowfish (CBC)"
    except Exception as e:
        raise ValueError(f"Blowfish decryption failed: {e}")

def triple_des_decrypt(cipher_text: str):
    try:
        data = base64.b64decode(cipher_text)
        if len(data) < TRIPLE_DES_BLOCK_SIZE:
            raise ValueError("Ciphertext too short for Triple DES-CBC")
        iv = data[:TRIPLE_DES_BLOCK_SIZE]
        ct = data[TRIPLE_DES_BLOCK_SIZE:]
        key_hex = input("Enter the Triple DES key (48 hex chars = 24 bytes): ").strip()
        key = bytes.fromhex(key_hex)
        if len(key) != 24:
            raise ValueError("Triple DES key must be 24 bytes (48 hex characters)")
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded = cipher.decrypt(ct)
        pt = unpad(padded, TRIPLE_DES_BLOCK_SIZE)
        return pt.decode(), "Triple DES (CBC)"
    except Exception as e:
        raise ValueError(f"Triple DES decryption failed: {e}")

def chacha20_decrypt(cipher_text: str):
    try:
        data = base64.b64decode(cipher_text)
        if len(data) < CHACHA20_NONCE_SIZE:
            raise ValueError("Ciphertext too short for ChaCha20")
        nonce = data[:CHACHA20_NONCE_SIZE]
        ct = data[CHACHA20_NONCE_SIZE:]
        key_hex = input("Enter the ChaCha20 key (64 hex chars = 32 bytes): ").strip()
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            raise ValueError("ChaCha20 key must be 32 bytes (64 hex characters)")
        cipher = ChaCha20.new(key=key, nonce=nonce)
        pt = cipher.decrypt(ct)
        return pt.decode(), "ChaCha20"
    except Exception as e:
        raise ValueError(f"ChaCha20 decryption failed: {e}")

def sha256_hash_decrypt(cipher_text: str):
    return "SHA-256 is a one-way cryptographic hash function and cannot be decrypted.", "SHA-256"

def main():
    print("🔐 Secure Decryption Tool (Educational Use Only)")
    print("Select the decryption technique:")
    print("1. AES (CBC mode)")
    print("2. RSA (OAEP)")
    print("3. Blowfish (CBC)")
    print("4. Triple DES (CBC)")
    print("5. ChaCha20")
    print("6. SHA-256 hash (info only)")
    
    choice = input("\nEnter your choice (1-6): ").strip()
    cipher_text = input("Enter the Base64-encoded cipher text: ").strip()

    techniques = {
        "1": aes_decrypt,
        "2": rsa_decrypt,
        "3": blowfish_decrypt,
        "4": triple_des_decrypt,
        "5": chacha20_decrypt,
        "6": sha256_hash_decrypt
    }

    if choice not in techniques:
        print("❌ Invalid choice. Please select 1–6.")
        sys.exit(1)

    try:
        result = techniques[choice](cipher_text)
        pt, technique_name = result
        print(f"\n✅ Technique used: {technique_name}")
        print(f"📄 Plain text: {pt}")
    except ValueError as ve:
        print(f"❌ Decryption error: {ve}")
    except UnicodeDecodeError:
        print("❌ Decryption succeeded but output is not valid UTF-8 text (may be binary data).")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()