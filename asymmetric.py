from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import hashlib
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()
print(public_key.export_key())
def derive_aes_key(secret: bytes, key_length: int = 32)->bytes:
    shake = hashlib.shake_256()
    shake.update(secret)
    return shake.digest(key_length)
def encrypt_message(message: bytes, public_key: RSA.RsaKey):
    aes_key = get_random_bytes(32)
    cipher = AES.new(aes_key, AES.MODE_GCM)
    nonce = cipher.nonce
    # encrypted_aes_key = public_key.encrypt(aes_key, PKCS1_OAEP.new(public_key))
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    return nonce, ciphertext, tag, encrypted_aes_key

def decrypt_message(nonce, ciphertext, tag, encrypted_aes_key, private_key: RSA.RsaKey):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode()

message = input("Enter the message to encrypt: ")
nonce, ciphertext, tag, encrypted_aes_key = encrypt_message(message, public_key)
print("Nonce:", nonce)
print("Ciphertext:", ciphertext)
print("Tag:", tag)
print("Encrypted AES Key:", encrypted_aes_key)

# Create a secure password hash using SHA-256 with a salt
correct_password = "secure123"  # You can change this to any password you want
salt = get_random_bytes(16)  # Generate a random salt
# Hash password with salt
password_hash = hashlib.pbkdf2_hmac('sha256', correct_password.encode(), salt, 100000)

print("Enter password to decrypt (you have 3 attempts)")
for _ in range(3):
    password_attempt = input("Password: ")
    # Hash the attempted password with the same salt
    attempt_hash = hashlib.pbkdf2_hmac('sha256', password_attempt.encode(), salt, 100000)
    
    if attempt_hash == password_hash:
        try:
            decrypted = decrypt_message(nonce, ciphertext, tag, encrypted_aes_key, private_key)
            print("Decrypted message:", decrypted)
        except Exception as e:
            print("Error during decryption:", str(e))
    else:
        print("Authentication failed: Incorrect password")