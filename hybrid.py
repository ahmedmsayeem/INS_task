import hashlib

def derive_substitution_key(hex_key):
    hex_key = hex_key.replace(" ", "")
    sub_key = ""
    for i in range(0, len(hex_key), 2):
        hex_pair = hex_key[i:i+2]
        dec = int(hex_pair, 16)
        letter = chr((dec % 26) + ord('A'))
        sub_key += letter
    return sub_key

def derive_transposition_order(hex_key, num_columns):
    key_bytes = bytes.fromhex(hex_key)
    hash_bytes = hashlib.sha256(key_bytes).digest()[:num_columns]
    indexed = list(enumerate(hash_bytes))
    sorted_indexed = sorted(indexed, key=lambda x: x[1])
    permutation = [idx for idx, _ in sorted_indexed]
    return permutation

def substitution_encrypt(plaintext, sub_key):
    plaintext = plaintext.upper()
    sub_key = sub_key.upper()
    cipher = ""
    key_index = 0
    for ch in plaintext:
        if ch.isalpha():
            p_val = ord(ch) - ord('A')
            k_val = ord(sub_key[key_index % len(sub_key)]) - ord('A')
            c_val = (p_val + k_val) % 26
            cipher += chr(c_val + ord('A'))
            key_index += 1
        else:
            cipher += ch
    return cipher

def substitution_decrypt(ciphertext, sub_key):
    ciphertext = ciphertext.upper()
    sub_key = sub_key.upper()
    plain = ""
    key_index = 0
    for ch in ciphertext:
        if ch.isalpha():
            c_val = ord(ch) - ord('A')
            k_val = ord(sub_key[key_index % len(sub_key)]) - ord('A')
            p_val = (c_val - k_val) % 26
            plain += chr(p_val + ord('A'))
            key_index += 1
        else:
            plain += ch
    return plain

def transposition_encrypt(text, permutation):
    n = len(permutation)
    if len(text) % n != 0:
        text += " " * (n - (len(text) % n))
    
    result = ""
    for i in range(0, len(text), n):
        block = list(text[i:i+n])
        new_block = [None] * n
        for j in range(n):
            new_block[j] = block[permutation[j]]
        result += "".join(new_block)
    return result

def inverse_permutation(permutation):
    n = len(permutation)
    inv = [0] * n
    for i, p in enumerate(permutation):
        inv[p] = i
    return inv

def transposition_decrypt(text, permutation):
    inv_perm = inverse_permutation(permutation)
    n = len(permutation)
    result = ""
    for i in range(0, len(text), n):
        block = list(text[i:i+n])
        original_block = [None] * n
        for j in range(n):
            original_block[j] = block[inv_perm[j]]
        result += "".join(original_block)
    return result

def encrypt(plaintext, hex_key, num_columns=3):
    sub_key = derive_substitution_key(hex_key)
    trans_order = derive_transposition_order(hex_key, num_columns)
    substituted = substitution_encrypt(plaintext, sub_key)
    final_cipher = transposition_encrypt(substituted, trans_order)
    return final_cipher

def decrypt(ciphertext, hex_key, num_columns=3):
    sub_key = derive_substitution_key(hex_key)
    trans_order = derive_transposition_order(hex_key, num_columns)
    reversed_trans = transposition_decrypt(ciphertext, trans_order)
    plain = substitution_decrypt(reversed_trans, sub_key)
    return plain

if __name__ == "__main__":
    hex_key = "2B7E151628AED2A6ABF7158809CF4F3C"
    plaintext = "HELLO WORLD"
    cipher_text = encrypt(plaintext, hex_key, num_columns=3)
    print("Ciphertext:", cipher_text)
    decrypted_text = decrypt(cipher_text, hex_key, num_columns=3)
    print("Decrypted Text:", decrypted_text)
