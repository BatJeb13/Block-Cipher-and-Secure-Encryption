import os
import random

import Q1
import Q2to5

MASK64 = (1 << 64) - 1


def forge_ciphertext(key, plaintext):

    # Convert m to bytes for the MAC
    m_bytes = plaintext.to_bytes(8, "big")

    # Step 1 : compute the MAC tag
    tag = Q2to5.MAC(key, m_bytes) & MASK64

    # Step 2: build CBC over two 64-bit blocks: B0 = m, B1 = t
    B0 = plaintext & MASK64
    B1 = tag & MASK64

    # Similar structure to stuff in Q2.py question 5
    # Fresh random IV (64 bits)
    iv = int.from_bytes(os.urandom(8), "big") & MASK64

    # First block C0
    X0 = B0 ^ iv
    C0 = Q1.Encrypt_ECB(X0, key) & MASK64

    # Second block: C1
    X1 = B1 ^ C0
    C1 = Q1.Encrypt_ECB(X1, key) & MASK64

    # As per the output of AuthEncrypt in Q2.py
    # Ciphertext format: IV || C0 || C1  (192-bit integer)
    ciphertext = (iv << 128) | (C0 << 64) | C1
    return ciphertext


# DEMO
# In the real attack, secret_key is recovered from Q6.
secret_key = random.getrandbits(64) & MASK64

# A message we legitimately encrypt (goes into the query set Q in the game)
m_query = 0x0123456789ABCDEF
c_query = Q2to5.AuthEncrypt(secret_key, m_query)

# Our forced message:
m_forge = 0xDEADBEEFCAFEBABE

# Forge a ciphertext for m_forge without calling AuthEncrypt on m_forge
c_forge = forge_ciphertext(secret_key, m_forge)

# Decrypt the forged ciphertext
dec_forge = Q2to5.AuthDecrypt(secret_key, c_forge)

print("Forgery successful?", dec_forge == m_forge)
