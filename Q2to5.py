import Q1

MASK64 = (1 << 64) - 1
BLOCKSIZE = 8  # bytes = 64 bits


# Helper function to pad messages
def padder(m):
    msg = bytearray(m)
    msg.append(0x80)  # 1 bit then 7 zeros

    # pad with zeros so that BEFORE the length field, size is multiple of 8 bytes
    while (len(msg) % BLOCKSIZE) != 0:
        msg.append(0x00)

    # append original length in bits as 8 bytes
    L_bits = len(m) * 8
    msg.extend(L_bits.to_bytes(8, "big"))

    blocks = []
    for i in range(0, len(msg), BLOCKSIZE):
        block_bytes = msg[i : i + BLOCKSIZE]
        block_int = int.from_bytes(block_bytes, "big")
        blocks.append(block_int)

    return blocks


# Question 2
def CompressionDavies_Meyer(k, x):
    k &= MASK64
    x &= MASK64

    cipher_out = Q1.Encrypt_ECB(plaintext=x, key=k) & MASK64
    new_chaining = (cipher_out ^ x) & MASK64
    return new_chaining


# Question 3
def Hash(IV, m):
    blocks = padder(m)
    h = IV & MASK64

    for block in blocks:
        h = CompressionDavies_Meyer(k=block, x=h)

    return h & MASK64


# Question 4
# IV = 0 for MAC, as per Q&A question
def MAC(k, m, iv=0):
    h = Hash(iv, m)
    tag = Q1.Encrypt_ECB(plaintext=h & MASK64, key=k & MASK64) & MASK64
    return tag


def Verify(key, message, tag):
    expected = MAC(key, message)
    return expected == tag


# Question 5
def AuthEncrypt(key, plaintext):
    # m as 8 vytes (64-bit int)
    m_bytes = plaintext.to_bytes(8, "big")

    # Get the tag
    tag = MAC(key, m_bytes)

    # Blocks for CBC: B0 = message, B1 = tag
    B0 = plaintext & MASK64
    B1 = tag & MASK64

    # As per Q&A,
    iv = 0

    # Basically doing cbc but putting the iv before input therefore i can use ecb directly
    X0 = B0 ^ iv
    C0 = Q1.Encrypt_ECB(X0, key) & MASK64

    # Second block
    X1 = B1 ^ C0
    C1 = Q1.Encrypt_ECB(X1, key) & MASK64

    # Ciphertext as integer: IV || C0 || C1 (192 bits)
    ciphertext = (iv << 128) | (C0 << 64) | C1
    return ciphertext


def AuthDecrypt(key, ciphertext):
    # Ouput from encryption is IV || C0 || C1 so I have to unpack the same way.
    # Parse IV || C0 || C1 from ciphertext
    iv = (ciphertext >> 128) & MASK64
    C0 = (ciphertext >> 64) & MASK64
    C1 = ciphertext & MASK64

    # Just heading backwards
    # CBC decryption:
    X1 = Q1.Decrypt_ECB(C1, key) & MASK64
    B1 = X1 ^ C0

    # B0 = D_k(C0) XOR IV
    X0 = Q1.Decrypt_ECB(C0, key) & MASK64
    B0 = X0 ^ iv

    # Extract m and tag
    m_int = B0 & MASK64
    tag = B1 & MASK64

    # Recompute tag and verify
    m_bytes = m_int.to_bytes(8, "big")

    # Verify tag
    if Verify(key, m_bytes, tag):
        return m_int
    else:
        return False
