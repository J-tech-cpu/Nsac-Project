import base64
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP, Blowfish, DES3, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import secrets

# Constants
AES_KEY_SIZE = 32      # 256 bits
AES_BLOCK_SIZE = 16    # 128 bits
BLOWFISH_KEY_SIZE = 16 # 128 bits
TRIPLE_DES_KEY_SIZE = 24  # 192 bits
CHACHA20_NONCE_SIZE = 12  # 96 bits
RSA_KEY_SIZE = 2048

def aes_encrypt(plain_text: str):
    key = get_random_bytes(AES_KEY_SIZE)
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plain_text.encode(), AES_BLOCK_SIZE)
    ct = cipher.encrypt(padded)
    return base64.b64encode(iv + ct), "AES (CBC)", key.hex()

def rsa_encrypt(plain_text: str):
    if len(plain_text.encode()) > 190:  # Approx limit for 2048-bit RSA + OAEP
        raise ValueError("Plain text too long for RSA encryption (max ~190 bytes).")
    key = RSA.generate(RSA_KEY_SIZE)
    public_key = key.publickey()
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ct = cipher_rsa.encrypt(plain_text.encode())
    return (
        base64.b64encode(ct),
        "RSA (OAEP)",
        public_key.export_key().decode(),
        key.export_key().decode()
    )

def blowfish_encrypt(plain_text: str):
    key = get_random_bytes(BLOWFISH_KEY_SIZE)
    iv = get_random_bytes(Blowfish.block_size)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    padded = pad(plain_text.encode(), Blowfish.block_size)
    ct = cipher.encrypt(padded)
    return base64.b64encode(iv + ct), "Blowfish (CBC)", key.hex()

def triple_des_encrypt(plain_text: str):
    key = get_random_bytes(TRIPLE_DES_KEY_SIZE)
    iv = get_random_bytes(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = pad(plain_text.encode(), DES3.block_size)
    ct = cipher.encrypt(padded)
    return base64.b64encode(iv + ct), "Triple DES (CBC)", key.hex()

def chacha20_encrypt(plain_text: str):
    key = get_random_bytes(32)
    nonce = get_random_bytes(CHACHA20_NONCE_SIZE)  # Must be 12 bytes
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ct = cipher.encrypt(plain_text.encode())
    return base64.b64encode(nonce + ct), "ChaCha20", key.hex()

def sha256_hash(plain_text: str):
    digest = hashlib.sha256(plain_text.encode()).digest()
    return base64.b64encode(digest), "SHA-256", None

def main():
    techniques = [aes_encrypt, rsa_encrypt, blowfish_encrypt, triple_des_encrypt, chacha20_encrypt, sha256_hash]
    plain_text = input("Enter the plain text: ").strip()
    if not plain_text:
        print("Error: Plain text cannot be empty.")
        return

    selected_technique = secrets.choice(techniques)
    try:
        result = selected_technique(plain_text)
        ct = result[0]
        technique_name = result[1]

        print(f"\nTechnique used: {technique_name}")
        if selected_technique == rsa_encrypt:
            _, _, public_key, private_key = result
            print(f"Public Key:\n{public_key}")
            print(f"Private Key:\n{private_key}")
        else:
            key = result[2]
            if key:
                print(f"Key (hex): {key}")

        print(f"Cipher text (Base64): {ct.decode()}")
    except ValueError as ve:
        print(f"Error: {ve}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()