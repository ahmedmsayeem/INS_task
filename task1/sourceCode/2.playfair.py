
def create_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = "".join(dict.fromkeys(key.upper()))  # Remove duplicates
    matrix = key + "".join([ch for ch in alphabet if ch not in key])
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_encrypt(plaintext, key):
    matrix = create_matrix(key)
    plaintext = plaintext.upper().replace("J", "I")
    if len(plaintext) % 2 != 0:
        plaintext += "X"
    
    cipher = ""
    for i in range(0, len(plaintext), 2):
        a, b = plaintext[i], plaintext[i+1]
        row_a, col_a = divmod(matrix.index([x for x in matrix if a in x][0]), 5)
        row_b, col_b = divmod(matrix.index([x for x in matrix if b in x][0]), 5)
        if row_a == row_b:
            cipher += matrix[row_a][(col_a + 1) % 5] + matrix[row_b][(col_b + 1) % 5]
        elif col_a == col_b:
            cipher += matrix[(row_a + 1) % 5][col_a] + matrix[(row_b + 1) % 5][col_b]
        else:
            cipher += matrix[row_a][col_b] + matrix[row_b][col_a]
    return cipher

plaintext = "HELLO"
key = "KEYWORD"
print(playfair_encrypt(plaintext, key))
