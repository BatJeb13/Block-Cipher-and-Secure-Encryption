import os  # Used for IV generation

# DO: hard code the sbox file into your code

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
BLOCKSIZE = 8  # bytes is 64 bits


# Make it a lookup variable
SBOX = [
    142,
    79,
    87,
    120,
    121,
    106,
    107,
    92,
    93,
    80,
    81,
    114,
    115,
    148,
    101,
    134,
    158,
    95,
    103,
    136,
    137,
    122,
    123,
    108,
    109,
    96,
    97,
    130,
    131,
    164,
    117,
    150,
    174,
    111,
    119,
    152,
    153,
    138,
    139,
    124,
    125,
    112,
    113,
    146,
    147,
    180,
    133,
    166,
    154,
    155,
    140,
    141,
    128,
    129,
    162,
    163,
    196,
    149,
    182,
    190,
    127,
    135,
    168,
    169,
    198,
    206,
    143,
    151,
    184,
    185,
    170,
    171,
    156,
    157,
    144,
    145,
    178,
    179,
    212,
    165,
    214,
    222,
    159,
    167,
    200,
    201,
    186,
    187,
    172,
    173,
    160,
    161,
    194,
    195,
    228,
    181,
    216,
    217,
    202,
    203,
    188,
    189,
    176,
    177,
    210,
    211,
    244,
    197,
    230,
    238,
    175,
    183,
    232,
    233,
    218,
    219,
    204,
    205,
    192,
    193,
    226,
    227,
    4,
    213,
    246,
    254,
    191,
    199,
    14,
    207,
    215,
    248,
    249,
    234,
    235,
    220,
    221,
    208,
    209,
    242,
    243,
    20,
    229,
    6,
    231,
    8,
    9,
    250,
    251,
    236,
    237,
    224,
    225,
    2,
    3,
    36,
    245,
    22,
    30,
    223,
    247,
    24,
    25,
    10,
    11,
    252,
    253,
    240,
    241,
    18,
    19,
    52,
    5,
    38,
    46,
    239,
    26,
    27,
    12,
    13,
    0,
    1,
    34,
    35,
    68,
    21,
    54,
    62,
    255,
    7,
    40,
    41,
    56,
    57,
    42,
    43,
    28,
    29,
    16,
    17,
    50,
    51,
    84,
    37,
    70,
    78,
    15,
    23,
    72,
    73,
    58,
    59,
    44,
    45,
    32,
    33,
    66,
    67,
    100,
    53,
    86,
    94,
    31,
    39,
    116,
    69,
    102,
    110,
    47,
    55,
    88,
    89,
    74,
    75,
    60,
    61,
    48,
    49,
    82,
    83,
    132,
    85,
    118,
    126,
    63,
    71,
    104,
    105,
    90,
    91,
    76,
    77,
    64,
    65,
    98,
    99,
]


def pad_block(m_int):
    # Convert integer to bytes
    m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8 or 1, "big")

    # PKCS#7 padding
    pad_len = 8 - (len(m_bytes) % 8)
    m_bytes += bytes([pad_len] * pad_len)

    # Convert padded bytes into 64-bit blocks
    blocks = []
    for i in range(0, len(m_bytes), 8):
        block = int.from_bytes(m_bytes[i : i + 8], "big")
        blocks.append(block)

    return blocks


def unpad_block(data_bytes):
    if len(data_bytes) == 0:
        return b""

    pad_len = data_bytes[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("paading is wrong")

    # Check padding bytes
    if data_bytes[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("paading is wrong")

    return data_bytes[:-pad_len]


def first32(text):
    return (text >> 32) & MASK32


def rotate_key(key):
    r = 33 % 64
    return (key << r) & MASK64 | (key >> (64 - r))


def Sbox(text):
    out = 0
    for i in range(4):
        shift = 8 * (3 - i)  # MSB first
        b = (text >> shift) & 0xFF  # extract byte
        sb = SBOX[b] & 0xFF  # S-box output
        out |= sb << shift  # put it back
    return out


def round(R, key):
    return Sbox(R) ^ (key & MASK32)


def getAllKeys(key):
    K = key & MASK64
    keys = []
    for i in range(6):
        K = rotate_key(K)
        keys.append(first32(K))
    return keys


def Encrypt_ECB(plaintext, key):
    L = (plaintext >> 32) & MASK32
    R = plaintext & MASK32

    keys = getAllKeys(key)

    for key in keys:
        new_L = R
        new_R = (L ^ round(R, key)) & MASK32

        L, R = new_L, new_R

    return ((L << 32) | R) & MASK64


def Decrypt_ECB(ciphertext, key):
    L = (ciphertext >> 32) & MASK32
    R = ciphertext & MASK32

    keys = getAllKeys(key)[::-1]  # reverses the order
    for key in keys:
        prev_R = L
        prev_L = (R ^ round(L, key)) & MASK32

        L, R = prev_L, prev_R
    return ((L << 32) | R) & MASK64


# Might need to put the IV within the C output
def Encrypt_CBC(plaintext_int, key):
    # Convert to blocks
    blocks = pad_block(plaintext_int)

    # Fresh random IV
    iv = int.from_bytes(os.urandom(8), "big") & MASK64

    C_prev = iv
    ciphertext_blocks = [iv]

    # CBC encryption
    for B in blocks:
        X = B ^ C_prev
        C = Encrypt_ECB(X, key) & MASK64
        ciphertext_blocks.append(C)
        C_prev = C

    # Convert all blocks into one big integer
    ciphertext = 0
    for c in ciphertext_blocks:
        ciphertext = (ciphertext << 64) | c

    return ciphertext


def Decrypt_CBC(ciphertext_int, key):
    # Break ciphertext into 64-bit blocks
    blocks = []
    temp = ciphertext_int
    while temp > 0:
        blocks.append(temp & MASK64)
        temp >>= 64
    blocks.reverse()

    iv = blocks[0]
    C_blocks = blocks[1:]

    P_bytes = b""
    C_prev = iv

    # CBC decryption
    for C in C_blocks:
        X = Decrypt_ECB(C, key) & MASK64
        P_block = (X ^ C_prev) & MASK64
        P_bytes += P_block.to_bytes(8, "big")
        C_prev = C

    # Remove PKCS#7 padding
    P_bytes = unpad_block(P_bytes)

    # Convert back to integer
    return int.from_bytes(P_bytes, "big")
