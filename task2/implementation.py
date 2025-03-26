from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.dh import generate_parameters
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from cryptography.hazmat.primitives.padding import PKCS7

class SecureKeyManagementSystem:
    def __init__(self):
        self.symmetric_keys = {}  # Store AES keys
        self.asymmetric_keys = {}  # Store RSA key pairs

    def generate_aes_key(self, key_id):
        key = os.urandom(32)  # Generate 256-bit AES key
        self.symmetric_keys[key_id] = key
        return base64.b64encode(key).decode()

    def generate_rsa_key_pair(self, user_id):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        self.asymmetric_keys[user_id] = (private_key, public_key)
        return public_key

    def encrypt_with_aes(self, key_id, plaintext):
        key = self.symmetric_keys[key_id]
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt_with_aes(self, key_id, encrypted_data):
        key = self.symmetric_keys[key_id]
        encrypted_data = base64.b64decode(encrypted_data)
        iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
        return plaintext.decode()

    def encrypt_with_rsa(self, user_id, plaintext):
        _, public_key = self.asymmetric_keys[user_id]
        encrypted = public_key.encrypt(
            plaintext.encode(),
            padding.PKCS1v15()
        )
        return base64.b64encode(encrypted).decode()

    def decrypt_with_rsa(self, user_id, encrypted_data):
        private_key, _ = self.asymmetric_keys[user_id]
        encrypted_data = base64.b64decode(encrypted_data)
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.PKCS1v15()
        )
        return decrypted.decode()

    def generate_diffie_hellman_key(self):
        parameters = generate_parameters(generator=2, key_size=2048)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def key_revocation(self, key_id):
        if key_id in self.symmetric_keys:
            del self.symmetric_keys[key_id]
        elif key_id in self.asymmetric_keys:
            del self.asymmetric_keys[key_id]
        return "Key Revoked Successfully"

# ---------------------- Test Cases ----------------------

# Create an instance of the KMS
kms = SecureKeyManagementSystem()

# Test Case 1: Symmetric Key Management
aes_key_id = "user123"
kms.generate_aes_key(aes_key_id)
aes_ciphertext = kms.encrypt_with_aes(aes_key_id, "Sensitive Data")
aes_decrypted_text = kms.decrypt_with_aes(aes_key_id, aes_ciphertext)
print("Decrypted AES:", aes_decrypted_text)  # Expected Output: Sensitive Data

# Test Case 2: Asymmetric Key Management using PKCS1v15 Padding
rsa_user = "userRSA"
kms.generate_rsa_key_pair(rsa_user)
rsa_enc_data = kms.encrypt_with_rsa(rsa_user, "Confidential")
rsa_dec_data = kms.decrypt_with_rsa(rsa_user, rsa_enc_data)
print("Decrypted RSA:", rsa_dec_data)  # Expected Output: Confidential

# Test Case 3: Diffie-Hellman Key Exchange (Basic test for key generation)
dh_private, dh_public = kms.generate_diffie_hellman_key()
print("DH Public Key:", dh_public)  # Expected: A public key object

# Test Case 4: Key Revocation Test
revocation_result = kms.key_revocation(aes_key_id)
print("Revocation Result:", revocation_result)  # Expected: Key Revoked Successfully

# Additional test: Attempt to decrypt AES data after revocation (should fail)
try:
    kms.decrypt_with_aes(aes_key_id, aes_ciphertext)
except Exception as e:
    print("Expected error after key revocation:", e)