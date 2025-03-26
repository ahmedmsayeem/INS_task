def vigenere_encrypt(plaintext, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plaintext = plaintext.upper().replace(" ", "")
    key = (key * (len(plaintext) // len(key))) + key[:len(plaintext) % len(key)]

    cipher = ""
    for i in range(len(plaintext)):
        p = plaintext[i]
        k = key[i]
        cipher += alphabet[(alphabet.index(p) + alphabet.index(k)) % 26]
    return cipher

plaintext = "ATTACKATDAWN"
key = "LEMON"
print(vigenere_encrypt(plaintext, key))
