from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
def derive_key(password: str, key_length: int = 32)->bytes:
    shake = hashlib.shake_256()
    shake.update(password.encode())
    return shake.digest(key_length)
def encrypt(message: str, password: str):
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_GCM)
    print(type(cipher))
    
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return nonce, ciphertext, tag

def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, password: str):
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except ValueError:
        return "Authentication failed"

message = input("Enter the message to encrypt: ")
password = input("Enter the password: ")
nonce, ciphertext, tag = encrypt(message, password)
print("Nonce:", nonce)
print("Ciphertext:", ciphertext)
print("Tag:", tag)

for _ in range(3):
    password = input("Enter the password: ")
    print("Decrypted message:", decrypt(nonce, ciphertext, tag, password))
    
    



