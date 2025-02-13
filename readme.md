    # Comparative Analysis of Classical Encryption Techniques

This project focuses on the comparative analysis of three classical encryption techniques: the **Playfair Cipher**, the **Hill Cipher**, and the **Vigenère Cipher**. It explores their encryption mechanisms, computational complexities, strengths, and weaknesses. Additionally, it delves into cryptanalysis methods for each cipher and discusses their vulnerabilities. Finally, a hybrid cipher design is proposed to mitigate the limitations of these classical methods.

## Table of Contents
1. [Introduction](#introduction)
2. [Encryption Techniques](#encryption-techniques)
    - [Playfair Cipher](#playfair-cipher)
    - [Hill Cipher](#hill-cipher)
    - [Vigenère Cipher](#vigenère-cipher)
3. [Cryptanalysis](#cryptanalysis)
    - [Playfair Cipher](#cryptanalysis-of-playfair-cipher)
    - [Hill Cipher](#cryptanalysis-of-hill-cipher)
    - [Vigenère Cipher](#cryptanalysis-of-vigenère-cipher)
4. [Hybrid Cipher Design](#hybrid-cipher-design)
5. [How to Use](#how-to-use)
6. [License](#license)

---

## Introduction
Classical encryption techniques are foundational to cryptography. While they are not secure by modern standards, they provide valuable insights into the evolution of cryptographic practices. This project systematically examines the Playfair, Hill, and Vigenère Ciphers to highlight their strengths, weaknesses, and vulnerabilities.

---

## Encryption Techniques

### Playfair Cipher
- **Mechanism:** Digraphic substitution using a 5x5 matrix based on a keyword.
- **Strengths:** Resists frequency analysis compared to monoalphabetic ciphers.
- **Weaknesses:** Limited key space and vulnerability to known plaintext attacks.

### Hill Cipher
- **Mechanism:** Polygraphic substitution based on linear algebra and matrix multiplication.
- **Strengths:** Encrypts multiple characters at once.
- **Weaknesses:** Vulnerable to known plaintext attacks; requires invertible key matrices.

### Vigenère Cipher
- **Mechanism:** Polyalphabetic substitution using a repeating keyword.
- **Strengths:** Reduces the effectiveness of frequency analysis.
- **Weaknesses:** Susceptible to Kasiski examination and frequency analysis if the keyword is short.

---

## Cryptanalysis

### Cryptanalysis of Playfair Cipher
- Techniques: Digraph frequency analysis, known plaintext attacks.
- Mathematical Weakness: Limited key space (~2^84 keys).

### Cryptanalysis of Hill Cipher
- Techniques: Reconstruction of the key matrix via known plaintext attacks.
- Mathematical Weakness: Small key matrices are more susceptible to attacks.

### Cryptanalysis of Vigenère Cipher
- Techniques: Kasiski examination, frequency analysis of ciphertext segments.
- Mathematical Weakness: Repetitive keywords create statistical patterns.

---

## Hybrid Cipher Design
The hybrid cipher combines elements of classical techniques to enhance security while retaining simplicity. By integrating multiple encryption layers, the design aims to address the individual vulnerabilities of each classical method.

---

## How to Use
1. Clone this repository:
   ```bash
   git clone https://github.com/ahmedmsayeem/INS_task.git
