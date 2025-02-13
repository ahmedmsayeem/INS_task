import numpy as np

def hill_encrypt(plaintext, key):
    n = int(len(key)**0.5)
    key_matrix = np.array([ord(c.upper()) - 65 for c in key]).reshape(n, n)
    plaintext = plaintext.upper()
    vectors = [ord(c) - 65 for c in plaintext]
    if len(vectors) % n != 0:
        vectors.append(23)  # X
    
    cipher = ""
    for i in range(0, len(vectors), n):
        block = np.array(vectors[i:i+n])
        encrypted = np.dot(key_matrix, block) % 26
        cipher += ''.join([chr(int(c) + 65) for c in encrypted])
    return cipher


plaintext = "ACT"
key = "GYBNQKURP"
ciphertext = hill_encrypt(plaintext, key)

print(f"Original: {plaintext}")
print(f"Encrypted: {ciphertext}")

